
#include "jailbreak.h"


unsigned int long long __readmsr_jailbreak(unsigned long __register) {
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
		kernel_base = &((uint8_t*)__readmsr_jailbreak(0xC0000082))[-KERN_405_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kernel_base;
		got_prison0 =   (void**)&kernel_ptr[KERN_405_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_405_ROOTVNODE];
	} else if (fw_version == 0x455) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr_jailbreak(0xC0000082))[-KERN_455_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kernel_base;
		got_prison0 =   (void**)&kernel_ptr[KERN_455_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_455_ROOTVNODE];
	} else if (fw_version == 0x501) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr_jailbreak(0xC0000082))[-KERN_501_XFAST_SYSCALL];

		// Kernel pointers resolving
		kernel_ptr = (uint8_t*)kernel_base;
		got_prison0 =   (void**)&kernel_ptr[KERN_501_PRISON_0];
		got_rootvnode = (void**)&kernel_ptr[KERN_501_ROOTVNODE];
	} else if (fw_version == 0x505) {
		// Kernel base resolving
		kernel_base = &((uint8_t*)__readmsr_jailbreak(0xC0000082))[-KERN_505_XFAST_SYSCALL];

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

int jailbreak(uint64_t fw_version) {
	struct kpayload_jailbreak_info kpayload_jailbreak_info;
	kpayload_jailbreak_info.fw_version = fw_version;
	kexec(&kpayload_jailbreak, &kpayload_jailbreak_info);
	return 0;
}