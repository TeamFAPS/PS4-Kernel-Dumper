/*****************************************************************
*
* ============== PS4 Kernel Dumper ===============
*
*	Thanks to:
*	- CelesteBlue for the rewriting (USB mode + cross FW compatibility)
*	- WildCard for his functional code
*	- Shadow for the copyout trick
*	- xvortex for the updated PS4 payload SDK
*	- CTurt for his PS4 payload SDK
*	- Specter for his Code Execution method and implementation
*	- qwertyoruiopz for his webkit and kernel exploits
*
******************************************************************/

#include "jailbreak.h"


//#define DEBUG_SOCKET // comment to use USB method

#define printf_notification(...) \
	do { \
		char message[256]; \
		snprintf(message, sizeof(message), ##__VA_ARGS__); \
		send_system_notification_with_text(message); \
	} while (0)

#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}

struct kpayload_get_fw_version_info
{
  uint64_t uaddr;
};

struct kpayload_get_fw_version_args
{
  void* syscall_handler;
  struct kpayload_get_fw_version_info* kpayload_get_fw_version_info;
};

int kpayload_get_fw_version(struct thread *td, struct kpayload_get_fw_version_args* args) {
	
	void* kernel_base = 0;

	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = 0;

	uint64_t fw_version = 0x666;

	// Kernel base resolving followed by kern_printf resolving
	if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		if (!memcmp((char*)(kernel_base+KERN_505_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
			fw_version = 0x505;
			copyout = (void *)(kernel_base + KERN_505_COPYOUT);
		} else if (!memcmp((char*)(kernel_base+KERN_501_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
			fw_version = 0x501;
			copyout = (void *)(kernel_base + KERN_501_COPYOUT);
		}
	} else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		if (!memcmp((char*)(kernel_base+KERN_455_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
			fw_version = 0x455;
			copyout = (void *)(kernel_base + KERN_455_COPYOUT);
		}
	} else if (!memcmp((char*)(&((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL]), (char[4]){0x7F, 0x45, 0x4C, 0x46}, 4)) {
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];
		if (!memcmp((char*)(kernel_base+KERN_405_PRINTF), (char[12]){0x55, 0x48, 0x89, 0xE5, 0x53, 0x48, 0x83, 0xEC, 0x58, 0x48, 0x8D, 0x1D}, 12)) {
			fw_version = 0x405;
			copyout = (void *)(kernel_base + KERN_405_COPYOUT);
		}
	} else return -1;

	// Put the fw version in userland so we can use it later
	uint64_t uaddr = args->kpayload_get_fw_version_info->uaddr;
	copyout(&fw_version, (uint64_t*)uaddr, 8);

	return 0;
}


struct kpayload_get_kbase_info
{
  uint64_t fw_version;
  uint64_t uaddr;
};

struct kpayload_get_kbase_args
{
  void* syscall_handler;
  struct kpayload_get_kbase_info* kpayload_get_kbase_info;
};

int kpayload_get_kbase(struct thread *td, struct kpayload_get_kbase_args* args) {
	
	void* kernel_base;

	int (*copyout)(const void *kaddr, void *uaddr, size_t len);

	uint64_t fw_version = args->kpayload_get_kbase_info->fw_version;

	if (fw_version == 0x405) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];
		
		// Kernel functions resolving
		copyout = (void *)(kernel_base + KERN_405_COPYOUT);
	} else if (fw_version == 0x455) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		
		// Kernel functions resolving
		copyout = (void *)(kernel_base + KERN_455_COPYOUT);
	} else if (fw_version == 0x501) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_501_XFAST_SYSCALL];
		
		// Kernel functions resolving
		copyout = (void *)(kernel_base + KERN_501_COPYOUT);
	} else if (fw_version == 0x505) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		
		// Kernel functions resolving
		copyout = (void *)(kernel_base + KERN_505_COPYOUT);
	} else return -1;

	// Put the kernel base in userland so we can use it later
	uint64_t uaddr = args->kpayload_get_kbase_info->uaddr;
	copyout(&kernel_base, (uint64_t*)uaddr, 8);

	return 0;
}


struct kpayload_kernel_dumper_info
{
  uint64_t fw_version;
  uint64_t uaddr;
  uint64_t kaddr;
  size_t size;
};

struct kpayload_kernel_dumper_args
{
  void* syscall_handler;
  struct kpayload_kernel_dumper_info* kpayload_kernel_dumper_info;
};

int kpayload_kernel_dumper(struct thread *td, struct kpayload_kernel_dumper_args* args) {
	
	void* kernel_base;
	
	int (*copyout)(const void *kaddr, void *uaddr, size_t len);
	void (*bzero)(void *b, size_t len);

	uint64_t fw_version = args->kpayload_kernel_dumper_info->fw_version;
	
	if (fw_version == 0x405) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];
		
		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + KERN_405_PRINTF);
		copyout = (void *)(kernel_base + KERN_405_COPYOUT);
		bzero = (void *)(kernel_base + KERN_405_BZERO);
	} else if (fw_version == 0x455) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];
		
		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + KERN_455_PRINTF);
		copyout = (void *)(kernel_base + KERN_455_COPYOUT);
		bzero = (void *)(kernel_base + KERN_455_BZERO);
	} else if (fw_version == 0x501) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_501_XFAST_SYSCALL];
		
		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + KERN_501_PRINTF);
		copyout = (void *)(kernel_base + KERN_501_COPYOUT);
		bzero = (void *)(kernel_base + KERN_501_BZERO);
	} else if (fw_version == 0x505) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];
		
		// Kernel functions resolving
		//int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + KERN_505_PRINTF);
		copyout = (void *)(kernel_base + KERN_505_COPYOUT);
		bzero = (void *)(kernel_base + KERN_505_BZERO);
	} else return -1;

	// Pull in arguments
	uint64_t kaddr = args->kpayload_kernel_dumper_info->kaddr;
	uint64_t uaddr = args->kpayload_kernel_dumper_info->uaddr;
	size_t size = args->kpayload_kernel_dumper_info->size;

	// Copyout into userland memory from the kaddr we specify
	int cpRet = copyout((uint64_t*)kaddr, (uint64_t*)uaddr, size);

	// If mapping doesn't exist then zero out that memory
	if (cpRet == -1) {
		//printfkernel("bzero at 0x%016llx\n", kaddr);
		bzero((uint64_t*)uaddr, size);
	}
	
	return cpRet;
}


void send_system_notification_with_text(char *message) {
	char notification_buf[512];
	sprintf(notification_buf, "%s\n\n\n\n\n\n\n", message);
	sceSysUtilSendSystemNotificationWithText(0x81, notification_buf);
}

#define KERNEL_CHUNK_SIZE	0x1000
#define KERNEL_CHUNK_NUMBER	0x69B8

int _main(struct thread *td) {
	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();
	
#ifdef DEBUG_SOCKET
	// Create our TCP server
	struct sockaddr_in server;
	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 0, 19);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	int sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	printfsocket("connected\n");
#endif
	
	uint64_t* fw_version_ptr = mmap(NULL, 0x8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // Allocate a buffer in userland
	struct kpayload_get_fw_version_info kpayload_get_fw_version_info;
	kpayload_get_fw_version_info.uaddr = (uint64_t)fw_version_ptr;
	kexec(&kpayload_get_fw_version, &kpayload_get_fw_version_info);
	
	jailbreak(*fw_version_ptr); // Patch some things in the kernel (sandbox, prison) to give to userland more privileges
	
	uint64_t* kernel_base_ptr = mmap(NULL, 0x8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // Allocate a buffer in userland
	struct kpayload_get_kbase_info kpayload_get_kbase_info;
	kpayload_get_kbase_info.fw_version = (uint64_t)*fw_version_ptr;
	kpayload_get_kbase_info.uaddr = (uint64_t)kernel_base_ptr;
	kexec(&kpayload_get_kbase, &kpayload_get_kbase_info);
	
	initSysUtil(); // Need the browser to have been jailbreaked first
#ifdef DEBUG_SOCKET
	printf_notification("PS4 Kernel Dumper to socket");
	printfsocket("PS4 FW version is: 0x%016llx\n", *fw_version_ptr);
	printfsocket("kernel base address is: 0x%016llx\n", *kernel_base_ptr);
#else
	printf_notification("PS4 Kernel Dumper to USB");
	char saveFile[64];
	int sf = -1;
	int row = 0;
	while (sf == -1) {
		sceKernelUsleep(100*1000);
		if (row >= 60) {
			printf_notification("No USB storage detected.\nPlease connect it.");
			row = 0;
		} else row += 1;
		sprintf(saveFile, "/mnt/usb%i/kernel_dump_fw_%03X.bin", row/10, *fw_version_ptr);
		sf = open(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0777);
	}
	printf_notification("\nUSB device detected.\n\nStarting kernel dumping to USB.");
	int percent = 0;
#endif
	uint64_t* dump = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // Allocate a 0x1000 buffer in userland
	// Loop on our kpayload_kernel_dumper (loop enough to dump up until GPU used memory)
	struct kpayload_kernel_dumper_info kpayload_kernel_dumper_info;
	uint64_t pos = 0;
	for (uint64_t i = 0; i < KERNEL_CHUNK_NUMBER; i++) {
		kpayload_kernel_dumper_info.fw_version = (uint64_t)*fw_version_ptr;
		kpayload_kernel_dumper_info.kaddr = (uint64_t)(*kernel_base_ptr + pos);
		kpayload_kernel_dumper_info.uaddr = (uint64_t)dump;
		kpayload_kernel_dumper_info.size = KERNEL_CHUNK_SIZE;
		// Call our copyout wrapper and write the userland buffer to USB
		kexec(&kpayload_kernel_dumper, &kpayload_kernel_dumper_info);
#ifdef DEBUG_SOCKET
		sceNetSend(sock, dump, KERNEL_CHUNK_SIZE, 0);
#else
		lseek(sf, pos, SEEK_SET);
		write(sf, (void*)dump, KERNEL_CHUNK_SIZE);
		if (i >= (percent+10)*KERNEL_CHUNK_NUMBER/100) {
			percent += 10;
			printf_notification("Kernel dumping to USB\nDone: %i\%%", percent);
		}
#endif
		pos = pos + KERNEL_CHUNK_SIZE;
	}
	printf_notification("Kernel successfully dumped !");

#ifdef DEBUG_SOCKET
	sceNetSocketClose(sock);
#else
	close(sf);
#endif
	
	//munmap(dump, 0x1000);

	return 0;
}