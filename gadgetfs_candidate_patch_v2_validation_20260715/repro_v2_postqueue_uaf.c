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
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_PATH "/dev/gadget/ep1in-bulk"
#define XFER_LEN 65
#define MAX_ROUNDS 4096

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
static int usbfd = -1;
static int rounds = 2048;
static atomic_int host_armed;
static atomic_int host_done;
static atomic_int host_errors;

static long xio_setup(unsigned nr, aio_context_t *c)
{
	return syscall(SYS_io_setup, nr, c);
}

static long xio_destroy(aio_context_t c)
{
	return syscall(SYS_io_destroy, c);
}

static long xio_submit(aio_context_t c, long nr, struct iocb **p)
{
	return syscall(SYS_io_submit, c, nr, p);
}

static long xio_getevents(aio_context_t c, long min, long nr,
			  struct io_event *ev, struct timespec *to)
{
	return syscall(SYS_io_getevents, c, min, nr, ev, to);
}

static void nsleep(long ns)
{
	struct timespec ts = { ns / 1000000000L, ns % 1000000000L };

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
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

static void prep_perms(void)
{
	for (int i = 0; i < 200; i++) {
		if (access(EP_PATH, F_OK) == 0) {
			if (chown(EP_PATH, 1000, 1000) || chmod(EP_PATH, 0666))
				perror("prepare endpoint permissions");
			return;
		}
		nsleep(5000000L);
	}
}

static int enable_ep(int fd)
{
	struct ep_msg m;

	memset(&m, 0, sizeof(m));
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
	int fd = open(path, O_RDONLY);
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

static int open_usbfs_dev(void)
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
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", de->d_name);
		if (read_trim(path, vid, sizeof(vid)))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", de->d_name);
		if (read_trim(path, pid, sizeof(pid)) || strcmp(vid, "1d6b") || strcmp(pid, "0104"))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/busnum", de->d_name);
		if (read_trim(path, bus, sizeof(bus)))
			continue;
		snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/devnum", de->d_name);
		if (read_trim(path, dev, sizeof(dev)))
			continue;
		snprintf(node, sizeof(node), "/dev/bus/usb/%03d/%03d", atoi(bus), atoi(dev));
		chmod(node, 0666);
		fd = open(node, O_RDWR | O_CLOEXEC);
		break;
	}
	closedir(dir);
	if (fd >= 0) {
		int ifc = 0;
		if (ioctl(fd, USBDEVFS_CLAIMINTERFACE, &ifc)) {
			close(fd);
			fd = -1;
		}
	}
	return fd;
}

static void *host_thread(void *unused)
{
	unsigned char data[XFER_LEN];

	(void)unused;
	pin_cpu(1);
	for (int i = 0; i < rounds; i++) {
		struct usbdevfs_bulktransfer bt;
		int ret;

		memset(data, 0, sizeof(data));
		memset(&bt, 0, sizeof(bt));
		bt.ep = 0x81;
		bt.len = XFER_LEN;
		bt.timeout = 2000;
		bt.data = data;
		atomic_store_explicit(&host_armed, i + 1, memory_order_release);
		ret = ioctl(usbfd, USBDEVFS_BULK, &bt);
		if (ret != XFER_LEN) {
			atomic_fetch_add(&host_errors, 1);
			break;
		}
		atomic_store_explicit(&host_done, i + 1, memory_order_release);
	}
	return NULL;
}

int main(int argc, char **argv)
{
	struct iocb *cbs, *one[1];
	struct io_event events[64];
	unsigned char *bufs;
	pthread_t host;
	int ep0, epfd, submitted = 0, completed = 0;

	if (argc > 1)
		rounds = atoi(argv[1]);
	if (rounds < 1 || rounds > MAX_ROUNDS)
		return 64;
	pin_cpu(0);
	mkdir("/dev/gadget", 0755);
	mount("gadgetfs", "/dev/gadget", "gadgetfs", 0, NULL);
	ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC);
	if (ep0 < 0 || write_device_desc(ep0))
		return 1;
	nsleep(1000000000L);
	prep_perms();
	usbfd = open_usbfs_dev();
	if (usbfd < 0)
		return 2;
	if (setgid(1000) || setuid(1000))
		return 3;
	epfd = open(EP_PATH, O_RDWR | O_CLOEXEC);
	if (epfd < 0 || enable_ep(epfd))
		return 4;
	if (xio_setup(rounds + 64, &ctx) < 0)
		return 5;
	cbs = calloc(rounds, sizeof(*cbs));
	bufs = aligned_alloc(64, (size_t)rounds * 128);
	if (!cbs || !bufs)
		return 6;
	memset(bufs, 'M', (size_t)rounds * 128);
	atomic_store(&host_armed, 0);
	atomic_store(&host_done, 0);
	atomic_store(&host_errors, 0);
	pthread_create(&host, NULL, host_thread, NULL);

	for (int i = 0; i < rounds; i++) {
		while (atomic_load_explicit(&host_armed, memory_order_acquire) < i + 1)
			sched_yield();
		nsleep(50000L);
		cbs[i].aio_data = (uint64_t)(uintptr_t)&cbs[i];
		cbs[i].aio_fildes = epfd;
		cbs[i].aio_lio_opcode = IOCB_CMD_PWRITE;
		cbs[i].aio_buf = (uint64_t)(uintptr_t)(bufs + (size_t)i * 128);
		cbs[i].aio_nbytes = XFER_LEN;
		one[0] = &cbs[i];
		if (xio_submit(ctx, 1, one) != 1)
			break;
		submitted++;
	}

	pthread_join(host, NULL);
	for (int tries = 0; completed < submitted && tries < 100; tries++) {
		struct timespec to = { 0, 100000000L };
		long want = submitted - completed;
		long n;

		if (want > 64)
			want = 64;
		n = xio_getevents(ctx, 1, want, events, &to);

		if (n > 0)
			completed += n;
		else if (n < 0)
			break;
	}
	fprintf(stderr, "uid=%d rounds=%d submitted=%d completed=%d host_done=%d host_errors=%d\n",
		getuid(), rounds, submitted, completed, atomic_load(&host_done),
		atomic_load(&host_errors));
	close(epfd);
	close(ep0);
	close(usbfd);
	xio_destroy(ctx);
	return submitted == rounds && completed == rounds && !atomic_load(&host_errors) ? 0 : 7;
}
