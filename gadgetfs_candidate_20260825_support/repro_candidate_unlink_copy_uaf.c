#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/usb/ch9.h>
#include <linux/usbdevice_fs.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_OUT_PATH "/dev/gadget/ep1out-bulk"
#define REQUEST_LEN 4096
#define HOST_LEN 512
#define MAX_BATCH 64

struct ep7 {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint8_t bEndpointAddress;
	uint8_t bmAttributes;
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

struct request_slot {
	struct iocb cb;
	struct iovec iov[2];
	unsigned char *buf1;
	unsigned char *buf2;
	atomic_int host_done;
	atomic_int cancel_done;
	int host_ret;
	int host_errno;
	long cancel_ret;
	int cancel_errno;
};

struct round_ctx {
	aio_context_t aio;
	int usbfd;
	int completion_efd;
	int batch;
	atomic_int start;
	struct request_slot *slots;
};

static long xio_setup(unsigned nr, aio_context_t *ctx)
{
	return syscall(SYS_io_setup, nr, ctx);
}

static long xio_destroy(aio_context_t ctx)
{
	return syscall(SYS_io_destroy, ctx);
}

static long xio_submit(aio_context_t ctx, long nr, struct iocb **iocbs)
{
	return syscall(SYS_io_submit, ctx, nr, iocbs);
}

static long xio_cancel(aio_context_t ctx, struct iocb *iocb,
			struct io_event *event)
{
	return syscall(SYS_io_cancel, ctx, iocb, event);
}

static long xio_getevents(aio_context_t ctx, long min_nr, long nr,
			  struct io_event *events, struct timespec *timeout)
{
	return syscall(SYS_io_getevents, ctx, min_nr, nr, events, timeout);
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

static int before_deadline(const struct timespec *deadline)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (now.tv_sec != deadline->tv_sec)
		return now.tv_sec < deadline->tv_sec;
	return now.tv_nsec < deadline->tv_nsec;
}

static struct timespec deadline_after(unsigned seconds)
{
	struct timespec deadline;

	clock_gettime(CLOCK_MONOTONIC, &deadline);
	deadline.tv_sec += seconds;
	return deadline;
}

static int write_device_desc(int fd)
{
	struct desc_blob d;
	ssize_t n;

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
	d.ep_out.bEndpointAddress = 1;
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

	n = write(fd, &d, sizeof(d));
	if (n != (ssize_t)sizeof(d)) {
		fprintf(stderr, "device descriptor write=%zd errno=%d\n", n,
			errno);
		return -1;
	}
	return 0;
}

static int wait_for_endpoint(void)
{
	struct timespec deadline = deadline_after(10);

	while (before_deadline(&deadline)) {
		if (access(EP_OUT_PATH, F_OK) == 0) {
			if (chown(EP_OUT_PATH, 1000, 1000) != 0)
				return -1;
			if (chmod(EP_OUT_PATH, 0666) != 0)
				return -1;
			return 0;
		}
		sched_yield();
	}
	errno = ETIMEDOUT;
	return -1;
}

static int enable_out_ep(int fd)
{
	struct ep_msg msg;
	ssize_t n;

	memset(&msg, 0, sizeof(msg));
	msg.tag = 1;
	msg.ep.bLength = sizeof(struct ep7);
	msg.ep.bDescriptorType = USB_DT_ENDPOINT;
	msg.ep.bEndpointAddress = 1;
	msg.ep.bmAttributes = USB_ENDPOINT_XFER_BULK;
	msg.ep.wMaxPacketSize = 64;

	n = write(fd, &msg, sizeof(msg));
	if (n != (ssize_t)sizeof(msg)) {
		fprintf(stderr, "endpoint descriptor write=%zd errno=%d\n", n,
			errno);
		return -1;
	}
	return 0;
}

static int read_trim(const char *path, char *out, size_t out_size)
{
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = read(fd, out, out_size - 1);
	close(fd);
	if (n <= 0)
		return -1;
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' '))
		out[--n] = '\0';
	return 0;
}

static int scan_usbfs_device(void)
{
	struct dirent *entry;
	DIR *dir;
	int fd = -1;

	dir = opendir("/sys/bus/usb/devices");
	if (!dir)
		return -1;

	while ((entry = readdir(dir)) != NULL) {
		char path[512];
		char vendor[32];
		char product[32];
		char bus[32];
		char dev[32];
		char node[128];

		if (entry->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path),
			 "/sys/bus/usb/devices/%s/idVendor", entry->d_name);
		if (read_trim(path, vendor, sizeof(vendor)) != 0)
			continue;
		snprintf(path, sizeof(path),
			 "/sys/bus/usb/devices/%s/idProduct", entry->d_name);
		if (read_trim(path, product, sizeof(product)) != 0)
			continue;
		if (strcmp(vendor, "1d6b") != 0 || strcmp(product, "0104") != 0)
			continue;
		snprintf(path, sizeof(path),
			 "/sys/bus/usb/devices/%s/busnum", entry->d_name);
		if (read_trim(path, bus, sizeof(bus)) != 0)
			continue;
		snprintf(path, sizeof(path),
			 "/sys/bus/usb/devices/%s/devnum", entry->d_name);
		if (read_trim(path, dev, sizeof(dev)) != 0)
			continue;
		snprintf(node, sizeof(node), "/dev/bus/usb/%03d/%03d",
			 atoi(bus), atoi(dev));
		if (chmod(node, 0666) != 0)
			continue;
		fd = open(node, O_RDWR | O_CLOEXEC);
		if (fd >= 0)
			break;
	}
	closedir(dir);
	return fd;
}

static int wait_for_usbfs_device(void)
{
	struct timespec deadline = deadline_after(10);
	int fd;

	while (before_deadline(&deadline)) {
		fd = scan_usbfs_device();
		if (fd >= 0)
			return fd;
		sched_yield();
	}
	errno = ETIMEDOUT;
	return -1;
}

static int wait_for_interface_claim(int fd, int interface)
{
	struct timespec deadline = deadline_after(10);
	int saved_errno = ETIMEDOUT;

	while (before_deadline(&deadline)) {
		if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &interface) == 0)
			return 0;
		saved_errno = errno;
		if (saved_errno != ENOENT && saved_errno != EAGAIN &&
		    saved_errno != EBUSY)
			break;
		sched_yield();
	}
	errno = saved_errno;
	return -1;
}

static void *host_thread(void *opaque)
{
	struct round_ctx *round = opaque;
	unsigned char data[HOST_LEN];
	int i;

	pin_cpu(1);
	memset(data, 'H', sizeof(data));
	while (!atomic_load_explicit(&round->start, memory_order_acquire))
		sched_yield();

	for (i = 0; i < round->batch; i++) {
		struct usbdevfs_bulktransfer transfer;

		memset(&transfer, 0, sizeof(transfer));
		transfer.ep = 1;
		transfer.len = sizeof(data);
		transfer.timeout = 2000;
		transfer.data = data;
		errno = 0;
		round->slots[i].host_ret =
			ioctl(round->usbfd, USBDEVFS_BULK, &transfer);
		round->slots[i].host_errno = errno;
		atomic_store_explicit(&round->slots[i].host_done, 1,
				      memory_order_release);
		while (!atomic_load_explicit(&round->slots[i].cancel_done,
					    memory_order_acquire))
			sched_yield();
	}
	return NULL;
}

static void *cancel_thread(void *opaque)
{
	struct round_ctx *round = opaque;
	int i;

	pin_cpu(0);
	while (!atomic_load_explicit(&round->start, memory_order_acquire))
		sched_yield();

	for (i = 0; i < round->batch; i++) {
		struct io_event event;
		struct pollfd pfd = {
			.fd = round->completion_efd,
			.events = POLLIN,
		};
		uint64_t count;

		while (!atomic_load_explicit(&round->slots[i].host_done,
					    memory_order_acquire))
			sched_yield();
		memset(&event, 0, sizeof(event));
		errno = 0;
		round->slots[i].cancel_ret =
			xio_cancel(round->aio, &round->slots[i].cb, &event);
		round->slots[i].cancel_errno = errno;
		if (poll(&pfd, 1, 5000) != 1 ||
		    read(round->completion_efd, &count, sizeof(count)) !=
			    (ssize_t)sizeof(count) ||
		    count != 1) {
			round->slots[i].cancel_ret = -2;
			round->slots[i].cancel_errno = ETIMEDOUT;
		}
		atomic_store_explicit(&round->slots[i].cancel_done, 1,
				      memory_order_release);
	}
	return NULL;
}

static int allocate_slots(struct request_slot *slots, struct iocb **iocbs,
			  int batch, int epfd, int completion_efd,
			  unsigned long round_number)
{
	int i;

	for (i = 0; i < batch; i++) {
		struct request_slot *slot = &slots[i];

		memset(slot, 0, sizeof(*slot));
		slot->buf1 = aligned_alloc(64, REQUEST_LEN / 2);
		slot->buf2 = aligned_alloc(64, REQUEST_LEN / 2);
		if (!slot->buf1 || !slot->buf2)
			return -1;
		memset(slot->buf1, 0, REQUEST_LEN / 2);
		memset(slot->buf2, 0, REQUEST_LEN / 2);
		slot->iov[0].iov_base = slot->buf1;
		slot->iov[0].iov_len = REQUEST_LEN / 2;
		slot->iov[1].iov_base = slot->buf2;
		slot->iov[1].iov_len = REQUEST_LEN / 2;
		atomic_init(&slot->host_done, 0);
		atomic_init(&slot->cancel_done, 0);

		slot->cb.aio_data = (round_number << 16) | (unsigned)i;
		slot->cb.aio_fildes = epfd;
		slot->cb.aio_lio_opcode = IOCB_CMD_PREADV;
		slot->cb.aio_buf = (uint64_t)(uintptr_t)slot->iov;
		slot->cb.aio_nbytes = 2;
		slot->cb.aio_flags = IOCB_FLAG_RESFD;
		slot->cb.aio_resfd = completion_efd;
		iocbs[i] = &slot->cb;
	}
	return 0;
}

static void free_slots(struct request_slot *slots, int batch)
{
	int i;

	for (i = 0; i < batch; i++) {
		free(slots[i].buf1);
		free(slots[i].buf2);
	}
}

static int wait_for_completions(aio_context_t aio, struct io_event *events,
				int batch)
{
	int event_total = 0;

	while (event_total < batch) {
		struct timespec timeout = {
			.tv_sec = 5,
			.tv_nsec = 0,
		};
		long got;

		got = xio_getevents(aio, 1, batch - event_total,
				    &events[event_total], &timeout);
		if (got <= 0)
			return -1;
		event_total += got;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct request_slot slots[MAX_BATCH];
	struct iocb *iocbs[MAX_BATCH];
	struct io_event events[MAX_BATCH];
	aio_context_t aio = 0;
	unsigned long total_einprogress = 0;
	unsigned long total_einval = 0;
	unsigned long total_other = 0;
	int rounds = 200;
	int batch = 32;
	int completion_efd = -1;
	int usbfd = -1;
	int epfd = -1;
	int ep0 = -1;
	int interface = 0;
	int round_number;

	if (argc > 1)
		rounds = atoi(argv[1]);
	if (argc > 2)
		batch = atoi(argv[2]);
	if (rounds <= 0 || batch <= 0 || batch > MAX_BATCH) {
		fprintf(stderr, "usage: %s [rounds] [batch<=%d]\n", argv[0],
			MAX_BATCH);
		return 1;
	}

	pin_cpu(2);
	ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC);
	if (ep0 < 0 || write_device_desc(ep0) != 0) {
		perror("gadget setup");
		return 2;
	}
	if (wait_for_endpoint() != 0) {
		perror("wait endpoint");
		return 3;
	}
	usbfd = wait_for_usbfs_device();
	if (usbfd < 0) {
		perror("wait usbfs device");
		return 4;
	}
	if (wait_for_interface_claim(usbfd, interface) != 0) {
		perror("claim interface");
		return 5;
	}
	if (setgid(1000) != 0 || setuid(1000) != 0) {
		perror("drop uid");
		return 6;
	}
	epfd = open(EP_OUT_PATH, O_RDWR | O_CLOEXEC);
	if (epfd < 0 || enable_out_ep(epfd) != 0) {
		perror("endpoint setup");
		return 7;
	}
	if (xio_setup(MAX_BATCH * 2, &aio) != 0) {
		perror("io_setup");
		return 8;
	}
	completion_efd = eventfd(0, EFD_CLOEXEC);
	if (completion_efd < 0) {
		perror("eventfd");
		return 9;
	}

	for (round_number = 0; round_number < rounds; round_number++) {
		struct round_ctx round;
		pthread_t host;
		pthread_t cancel;
		int i;

		if (allocate_slots(slots, iocbs, batch, epfd, completion_efd,
				   (unsigned long)round_number) != 0)
			return 10;
		memset(&round, 0, sizeof(round));
		round.aio = aio;
		round.usbfd = usbfd;
		round.completion_efd = completion_efd;
		round.batch = batch;
		round.slots = slots;
		atomic_init(&round.start, 0);

		if (pthread_create(&host, NULL, host_thread, &round) != 0 ||
		    pthread_create(&cancel, NULL, cancel_thread, &round) != 0)
			return 11;
		errno = 0;
		if (xio_submit(aio, batch, iocbs) != batch) {
			fprintf(stderr, "round=%d submit errno=%d\n", round_number,
				errno);
			return 12;
		}
		atomic_store_explicit(&round.start, 1, memory_order_release);
		pthread_join(host, NULL);
		pthread_join(cancel, NULL);

		for (i = 0; i < batch; i++) {
			if (slots[i].host_ret != HOST_LEN) {
				fprintf(stderr,
					"round=%d slot=%d host_ret=%d errno=%d\n",
					round_number, i, slots[i].host_ret,
					slots[i].host_errno);
				return 13;
			}
			if (slots[i].cancel_ret == -1 &&
			    slots[i].cancel_errno == EINPROGRESS)
				total_einprogress++;
			else if (slots[i].cancel_ret == -1 &&
				 slots[i].cancel_errno == EINVAL)
				total_einval++;
			else
				total_other++;
		}

		memset(events, 0, sizeof(events));
		if (wait_for_completions(aio, events, batch) != 0) {
			fprintf(stderr, "round=%d completion wait failed errno=%d\n",
				round_number, errno);
			return 14;
		}
		for (i = 0; i < batch; i++) {
			if (events[i].res != HOST_LEN || events[i].res2 != 0) {
				fprintf(stderr,
					"round=%d event=%d res=%lld res2=%lld\n",
					round_number, i, (long long)events[i].res,
					(long long)events[i].res2);
				return 15;
			}
		}
		free_slots(slots, batch);

		if ((round_number + 1) % 10 == 0 || round_number + 1 == rounds)
			fprintf(stderr,
				"rounds=%d requests=%d cancel_einprogress=%lu "
				"cancel_einval=%lu cancel_other=%lu\n",
				round_number + 1, (round_number + 1) * batch,
				total_einprogress, total_einval, total_other);
	}

	close(completion_efd);
	xio_destroy(aio);
	close(epfd);
	close(usbfd);
	close(ep0);
	return total_other == 0 ? 0 : 16;
}
