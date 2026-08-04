#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
#include <linux/usb/ch9.h>
#include <linux/usbdevice_fs.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_PATH "/dev/gadget/ep1in-bulk"
#define XFER_LEN 65
#define ROUNDS 64

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

struct host_req {
	struct usbdevfs_urb urb;
	unsigned char data[XFER_LEN];
};

static long xio_setup(unsigned nr, aio_context_t *ctx)
{
	return syscall(SYS_io_setup, nr, ctx);
}

static long xio_submit(aio_context_t ctx, struct iocb **iocb)
{
	return syscall(SYS_io_submit, ctx, 1, iocb);
}

static long xio_getevents(aio_context_t ctx, long nr, struct io_event *events)
{
	return syscall(SYS_io_getevents, ctx, 1, nr, events, NULL);
}

static void pin_cpu0(void)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(0, &set);
	sched_setaffinity(0, sizeof(set), &set);
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
		chmod(node, 0666);
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

	for (unsigned i = 0; i < 1000000; i++) {
		fd = open_usb_device();
		if (fd >= 0)
			return fd;
		sched_yield();
	}
	return -1;
}

static int prepare_endpoint_permissions(void)
{
	for (unsigned i = 0; i < 1000000; i++) {
		if (!access(EP_PATH, F_OK))
			return chown(EP_PATH, 1000, 1000) || chmod(EP_PATH, 0666);
		sched_yield();
	}
	return -1;
}

int main(void)
{
	struct host_req *host;
	struct iocb *cbs, *one[1];
	struct io_event *events;
	unsigned char *bufs;
	aio_context_t ctx = 0;
	int ep0, epfd, usbfd;
	int host_submitted = 0, host_done = 0;
	int submitted = 0, completed = 0;

	pin_cpu0();
	mkdir("/dev/gadget", 0755);
	mount("gadgetfs", "/dev/gadget", "gadgetfs", 0, NULL);
	ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC);
	if (ep0 < 0 || write_descriptors(ep0))
		return 1;
	if (prepare_endpoint_permissions())
		return 2;
	usbfd = wait_for_usb_device();
	if (usbfd < 0)
		return 3;
	if (setgid(1000) || setuid(1000))
		return 4;
	epfd = open(EP_PATH, O_RDWR | O_CLOEXEC);
	if (epfd < 0 || enable_endpoint(epfd))
		return 5;
	if (xio_setup(ROUNDS + 64, &ctx) < 0)
		return 6;

	host = calloc(ROUNDS, sizeof(*host));
	cbs = calloc(ROUNDS, sizeof(*cbs));
	events = calloc(ROUNDS, sizeof(*events));
	bufs = aligned_alloc(64, ROUNDS * 128UL);
	if (!host || !cbs || !events || !bufs)
		return 7;
	memset(bufs, 'M', ROUNDS * 128UL);

	for (int i = 0; i < ROUNDS; i++) {
		host[i].urb.type = USBDEVFS_URB_TYPE_BULK;
		host[i].urb.endpoint = 0x81;
		host[i].urb.buffer = host[i].data;
		host[i].urb.buffer_length = XFER_LEN;
		host[i].urb.usercontext = &host[i];
		if (ioctl(usbfd, USBDEVFS_SUBMITURB, &host[i].urb))
			break;
		host_submitted++;
	}

	for (int i = 0; i < host_submitted; i++) {
		cbs[i].aio_data = (uint64_t)(uintptr_t)&cbs[i];
		cbs[i].aio_fildes = epfd;
		cbs[i].aio_lio_opcode = IOCB_CMD_PWRITE;
		cbs[i].aio_buf = (uint64_t)(uintptr_t)(bufs + i * 128UL);
		cbs[i].aio_nbytes = XFER_LEN;
		one[0] = &cbs[i];
		if (xio_submit(ctx, one) != 1)
			break;
		submitted++;
	}

	while (host_done < submitted) {
		struct usbdevfs_urb *done = NULL;

		if (ioctl(usbfd, USBDEVFS_REAPURB, &done))
			break;
		if (!done || done->status || done->actual_length != XFER_LEN)
			break;
		host_done++;
	}
	while (completed < submitted) {
		long n = xio_getevents(ctx, submitted - completed,
				       events + completed);

		if (n <= 0)
			break;
		completed += n;
	}

	fprintf(stderr, "uid=%d host=%d/%d aio=%d/%d\n", getuid(), host_done,
		host_submitted, completed, submitted);
	return host_submitted == ROUNDS && submitted == ROUNDS &&
	       host_done == ROUNDS && completed == ROUNDS ? 0 : 8;
}
