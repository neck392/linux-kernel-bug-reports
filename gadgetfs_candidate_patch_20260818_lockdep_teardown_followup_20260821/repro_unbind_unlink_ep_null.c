#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/usb/ch9.h>
#include <linux/usbdevice_fs.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_PATH "/dev/gadget/ep1in-bulk"
#define XFER_LEN 65

struct ep7 {
	uint8_t bLength, bDescriptorType, bEndpointAddress, bmAttributes;
	uint16_t wMaxPacketSize;
	uint8_t bInterval;
} __attribute__((packed));

struct desc_blob {
	uint32_t tag;
	struct usb_config_descriptor cfg;
	struct usb_interface_descriptor intf;
	struct ep7 ep_out, ep_in;
	struct usb_device_descriptor dev;
} __attribute__((packed));

struct ep_msg {
	uint32_t tag;
	struct ep7 ep;
} __attribute__((packed));

static aio_context_t ctx;
static struct iocb cb;
static atomic_int cancel_ready;
static atomic_int start_cancel;
static atomic_int cancel_done;
static atomic_int release_cancel;
static int scheduler_error;
static long cancel_ret;
static int cancel_errno;

static inline void cpu_pause(void)
{
	__asm__ __volatile__("pause");
}

static long xio_setup(unsigned nr, aio_context_t *c)
{
	return syscall(SYS_io_setup, nr, c);
}

static long xio_destroy(aio_context_t c)
{
	return syscall(SYS_io_destroy, c);
}

static long xio_submit(aio_context_t c, struct iocb **list)
{
	return syscall(SYS_io_submit, c, 1, list);
}

static long xio_cancel(aio_context_t c, struct iocb *iocb,
		       struct io_event *event)
{
	return syscall(SYS_io_cancel, c, iocb, event);
}

static long xio_getevents(aio_context_t c, long min_nr, long nr,
			  struct io_event *events, struct timespec *timeout)
{
	return syscall(SYS_io_getevents, c, min_nr, nr, events, timeout);
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set)) {
		perror("sched_setaffinity");
		exit(20);
	}
}

static int write_descriptors(int fd)
{
	struct desc_blob d = { };

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
	d.intf.bNumEndpoints = 2;
	d.intf.bInterfaceClass = 0xff;
	d.ep_out.bLength = sizeof(struct ep7);
	d.ep_out.bDescriptorType = USB_DT_ENDPOINT;
	d.ep_out.bEndpointAddress = 1;
	d.ep_out.bmAttributes = USB_ENDPOINT_XFER_BULK;
	d.ep_out.wMaxPacketSize = 64;
	d.ep_in = d.ep_out;
	d.ep_in.bEndpointAddress = 0x81;
	d.dev.bLength = USB_DT_DEVICE_SIZE;
	d.dev.bDescriptorType = USB_DT_DEVICE;
	d.dev.bcdUSB = 0x0200;
	d.dev.bDeviceClass = USB_CLASS_VENDOR_SPEC;
	d.dev.bMaxPacketSize0 = 64;
	d.dev.idVendor = 0x1d6b;
	d.dev.idProduct = 0x0104;
	d.dev.bcdDevice = 1;
	d.dev.bNumConfigurations = 1;
	return write(fd, &d, sizeof(d)) == (ssize_t)sizeof(d) ? 0 : -1;
}

static int enable_endpoint(int fd)
{
	struct ep_msg m = { };

	m.tag = 1;
	m.ep.bLength = sizeof(struct ep7);
	m.ep.bDescriptorType = USB_DT_ENDPOINT;
	m.ep.bEndpointAddress = 0x81;
	m.ep.bmAttributes = USB_ENDPOINT_XFER_BULK;
	m.ep.wMaxPacketSize = 64;
	return write(fd, &m, sizeof(m)) == (ssize_t)sizeof(m) ? 0 : -1;
}

static int read_trim(const char *path, char *out, size_t size)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, out, size - 1);
	close(fd);
	if (n <= 0)
		return -1;
	out[n] = 0;
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' '))
		out[--n] = 0;
	return 0;
}

static int open_usb_device(void)
{
	DIR *dir = opendir("/sys/bus/usb/devices");
	struct dirent *de;
	char path[512], vid[32], pid[32], bus[32], dev[32], node[128];
	int fd = -1;

	if (!dir)
		return -1;
	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor",
			 de->d_name);
		if (read_trim(path, vid, sizeof(vid)))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct",
			 de->d_name);
		if (read_trim(path, pid, sizeof(pid)) || strcmp(vid, "1d6b") ||
		    strcmp(pid, "0104"))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/busnum",
			 de->d_name);
		if (read_trim(path, bus, sizeof(bus)))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/devnum",
			 de->d_name);
		if (read_trim(path, dev, sizeof(dev)))
			continue;
		snprintf(node, sizeof(node), "/dev/bus/usb/%03d/%03d",
			 atoi(bus), atoi(dev));
		fd = open(node, O_RDWR | O_CLOEXEC);
		break;
	}
	closedir(dir);
	if (fd >= 0) {
		int intf = 0;

		if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &intf)) {
			close(fd);
			fd = -1;
		}
	}
	return fd;
}

static int wait_for_usb_device(void)
{
	int fd;

	for (unsigned int i = 0; i < 1000000; i++) {
		fd = open_usb_device();
		if (fd >= 0)
			return fd;
		sched_yield();
	}
	return -1;
}

static int wait_for_endpoint(void)
{
	for (unsigned int i = 0; i < 1000000; i++) {
		if (!access(EP_PATH, F_OK))
			return 0;
		sched_yield();
	}
	return -1;
}

static void *cancel_thread(void *unused)
{
	struct sched_param param = { .sched_priority = 10 };
	struct io_event event = { };

	(void)unused;
	pin_cpu(0);
	if (sched_setscheduler(0, SCHED_FIFO, &param))
		scheduler_error = errno;
	atomic_store_explicit(&cancel_ready, 1, memory_order_release);
	while (!atomic_load_explicit(&start_cancel, memory_order_acquire))
		cpu_pause();

	errno = 0;
	cancel_ret = xio_cancel(ctx, &cb, &event);
	cancel_errno = errno;
	atomic_store_explicit(&cancel_done, 1, memory_order_release);

	while (!atomic_load_explicit(&release_cancel, memory_order_acquire))
		cpu_pause();
	return NULL;
}

int main(void)
{
	struct io_event event = { };
	unsigned char *buffer;
	struct iocb *list[1] = { &cb };
	pthread_t thread;
	long submit_ret, event_count, destroy_ret;
	int ep0, epfd, usbfd;

	pin_cpu(1);
	mkdir("/dev/gadget", 0755);
	if (mount("gadgetfs", "/dev/gadget", "gadgetfs", 0, NULL) &&
	    errno != EBUSY) {
		perror("mount gadgetfs");
		return 1;
	}
	ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC);
	if (ep0 < 0 || write_descriptors(ep0))
		return 2;
	if (wait_for_endpoint())
		return 3;
	usbfd = wait_for_usb_device();
	if (usbfd < 0)
		return 4;
	if (chown(EP_PATH, 1000, 1000) || chmod(EP_PATH, 0666))
		return 5;

	atomic_store(&cancel_ready, 0);
	atomic_store(&start_cancel, 0);
	atomic_store(&cancel_done, 0);
	atomic_store(&release_cancel, 0);
	scheduler_error = 0;
	cancel_ret = -2;
	cancel_errno = 0;
	if (pthread_create(&thread, NULL, cancel_thread, NULL))
		return 6;
	while (!atomic_load_explicit(&cancel_ready, memory_order_acquire))
		sched_yield();
	if (scheduler_error) {
		fprintf(stderr, "sched_setscheduler failed: %s\n",
			strerror(scheduler_error));
		return 7;
	}

	if (setgid(1000) || setuid(1000))
		return 8;
	epfd = open(EP_PATH, O_RDWR | O_CLOEXEC);
	if (epfd < 0 || enable_endpoint(epfd))
		return 9;
	if (xio_setup(64, &ctx) < 0)
		return 10;

	buffer = aligned_alloc(64, 128);
	if (!buffer)
		return 11;
	memset(buffer, 'U', 128);
	memset(&cb, 0, sizeof(cb));
	cb.aio_data = 0x554e42494e44ULL;
	cb.aio_fildes = epfd;
	cb.aio_lio_opcode = IOCB_CMD_PWRITE;
	cb.aio_buf = (uint64_t)(uintptr_t)buffer;
	cb.aio_nbytes = XFER_LEN;

	errno = 0;
	submit_ret = xio_submit(ctx, list);
	if (submit_ret != 1) {
		fprintf(stderr, "io_submit=%ld errno=%d\n", submit_ret, errno);
		return 12;
	}

	atomic_store_explicit(&start_cancel, 1, memory_order_release);
	while (!atomic_load_explicit(&cancel_done, memory_order_acquire))
		sched_yield();
	if (cancel_ret != -1 || cancel_errno != EINPROGRESS) {
		fprintf(stderr, "io_cancel=%ld errno=%d\n", cancel_ret,
			cancel_errno);
		return 13;
	}

	close(ep0);
	atomic_store_explicit(&release_cancel, 1, memory_order_release);
	pthread_join(thread, NULL);

	event_count = xio_getevents(ctx, 0, 1, &event, NULL);
	destroy_ret = xio_destroy(ctx);
	fprintf(stderr,
		"uid=%d submit=%ld cancel=%ld cancel_errno=%d events=%ld "
		"res=%lld destroy=%ld\n",
		getuid(), submit_ret, cancel_ret, cancel_errno, event_count,
		event_count == 1 ? (long long)event.res : 0, destroy_ret);

	close(epfd);
	close(usbfd);
	free(buffer);
	return 0;
}
