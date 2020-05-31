/*****************************************************************
*
* ============== PS4 Kernel Dumper ===============
*
*	Thanks to:
*	- SocraticBliss for maintainability and output timestamp
*	- CelesteBlue for the rewriting (USB mode + cross FW compatibility)
*	- WildCard for his functional code
*	- Shadow for the copyout trick
*	- xvortex for the updated PS4 payload SDK
*	- CTurt for his PS4 payload SDK
*	- Specter for his Code Execution method and implementation
*	- qwertyoruiopz for his webkit and kernel exploits
*
******************************************************************/

#include "kernel_utils.h"

//#define DEBUG_SOCKET // comment to use USB method
#define KERNEL_CHUNK_SIZE	0x1000
#define KERNEL_CHUNK_NUMBER	0x69B8

#define notification(...)									\
	do {													\
		char message[256];									\
		snprintf(message, sizeof(message), ##__VA_ARGS__);	\
		send_system_notification_with_text(message);		\
	} while (0)

#ifdef DEBUG_SOCKET
#define socket(format, ...)									\
	do {													\
		char buffer[512];									\
		int size = sprintf(buffer, format, ##__VA_ARGS__);	\
		sceNetSend(sock, buffer, size, 0);					\
	} while(0)

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))
#endif

void send_system_notification_with_text(char *message)
{
	char notification_buf[512];
	sprintf(notification_buf, "%s\n\n\n\n\n\n\n", message);
	sceSysUtilSendSystemNotificationWithText(0x81, notification_buf);
}

int _main(struct thread *td)
{
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
	server.sin_addr.s_addr = IP(192, 168, 1, 189);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	
	int flag = 1;
	int sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
	
	socket("connected\n");

#endif

	uint64_t fw_version = get_fw_version();
	
	// Patch some things in the kernel (sandbox, prison) to give userland more privileges
	jailbreak(fw_version);
	
	uint64_t kernel_base = get_kernel_base(fw_version);
	
	// Need the browser to have been jailbroken first
	initSysUtil(); 

#ifdef DEBUG_SOCKET	

	notification("PS4 Kernel Dumper to socket");
	
	socket("PS4 FW version is: 0x%016llx\n", fw_version);
	socket("kernel base address is: 0x%016llx\n", kernel_base);

#else

	notification("PS4 Kernel Dumper to USB");
	
	int ret = -1;
	int row = 0;
	char saveFile[64];
	time_t now = time(NULL);
	
	while (ret == -1) {
		sceKernelUsleep(100 * 1000);
		
		if (row >= 60) {
			notification("No USB storage detected.\nPlease connect it.");
			row = 0;
		} else row += 1;
		
		sprintf(saveFile, "/mnt/usb%i/kernel_dump_fw_%03X_%i.bin", row/10, fw_version, (int)now);
		ret = open(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0777);	 
	}
	
	notification("USB storage detected.\n\nDumping Kernel to USB. Please wait as this might take a while...");

#endif

	// Allocate a 0x1000 buffer in userland
	uint64_t *dump = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); 
	
	// Loop on our kpayload_kernel_dumper (loop enough to dump up until GPU used memory)
	uint64_t pos = 0;
	for (uint64_t i = 0; i < KERNEL_CHUNK_NUMBER; i++) {
		dump_kernel(fw_version, kernel_base + pos, dump, KERNEL_CHUNK_SIZE); // Call our kernel copyout wrapper

#ifdef DEBUG_SOCKET

		// Send the userland buffer to socket
		sceNetSend(sock, dump, KERNEL_CHUNK_SIZE, 0); 

#else

		// Write the userland buffer to USB
		lseek(ret, pos, SEEK_SET);
		write(ret, (void *)dump, KERNEL_CHUNK_SIZE);

#endif
		
		pos += KERNEL_CHUNK_SIZE;
	}
	
	notification("Kernel successfully dumped!\n\nRebooting...");

#ifdef DEBUG_SOCKET

	sceNetSocketClose(sock);
	
#else
	
	close(ret);
	
#endif
	
	munmap(dump, 0x1000);
	
	syscall(55, 0);
	
	return 0;
}