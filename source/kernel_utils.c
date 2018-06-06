
#include "kernel_utils.h"


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


int kpayload_jailbreak(struct thread *td, struct kpayload_jailbreak_args* args) {
	
	struct filedesc* fd;
	struct ucred* cred;
	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base;
	uint8_t* kernel_ptr;
	void** got_prison0;
	void** got_rootvnode;

	uint64_t fw_version = args->kpayload_jailbreak_info->fw_version;
	
	if (fw_version == 0x405) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_405_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kernel_base;
		got_prison0 =   (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];
	} else if (fw_version == 0x455) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kernel_base;
		got_prison0 =   (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];
	} else if (fw_version == 0x501) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_501_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kernel_base;
		got_prison0 =   (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];
	} else if (fw_version == 0x505) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_505_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kernel_base;
		got_prison0 =   (void**)&kernel_ptr[KERN_505_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_505_ROOTVNODE];
	} else return -1;
	
	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Escalate ucred privs, needed for userland access to the filesystem e.g mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcessAuthorityId = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcessAuthorityId = 0x3801000000000013; // Max userland paid
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Max capability

	return 0;
}


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


uint64_t get_fw_version(void) {
	uint64_t fw_version = 0x666;
	uint64_t* fw_version_ptr = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // Allocate a buffer in userland
	struct kpayload_get_fw_version_info kpayload_get_fw_version_info;
	kpayload_get_fw_version_info.uaddr = (uint64_t)fw_version_ptr;
	kexec(&kpayload_get_fw_version, &kpayload_get_fw_version_info);
	memcpy(&fw_version, fw_version_ptr, 8);
	munmap(fw_version_ptr, 8);
	return fw_version;
}

int jailbreak(uint64_t fw_version) {
	struct kpayload_jailbreak_info kpayload_jailbreak_info;
	kpayload_jailbreak_info.fw_version = fw_version;
	kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);
	return 0;
}

uint64_t get_kernel_base(uint64_t fw_version) {
	uint64_t kernel_base = -1;
	uint64_t* kernel_base_ptr = mmap(NULL, 8, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0); // Allocate a buffer in userland
	struct kpayload_get_kbase_info kpayload_get_kbase_info;
	kpayload_get_kbase_info.fw_version = fw_version;
	kpayload_get_kbase_info.uaddr = (uint64_t)kernel_base_ptr;
	kexec(&kpayload_get_kbase, &kpayload_get_kbase_info);
	memcpy(&kernel_base, kernel_base_ptr, 8);
	munmap(kernel_base_ptr, 8);
	return kernel_base;
}

uint64_t dump_kernel(uint64_t fw_version, uint64_t kaddr, uint64_t* dump, size_t size) {
	struct kpayload_kernel_dumper_info kpayload_kernel_dumper_info;
	kpayload_kernel_dumper_info.fw_version = fw_version;
	kpayload_kernel_dumper_info.kaddr = kaddr;
	kpayload_kernel_dumper_info.uaddr = (uint64_t)dump;
	kpayload_kernel_dumper_info.size = size;
	kexec(&kpayload_kernel_dumper, &kpayload_kernel_dumper_info);
	return 0;
}