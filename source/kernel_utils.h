#ifndef __KERNEL_UTILS_H__
#define __KERNEL_UTILS_H__

#include "ps4.h"
#include "fw_defines.h"


struct auditinfo_addr {
	/*
	4	ai_auid;
	8	ai_mask;
	24	ai_termid;
	4	ai_asid;
	8	ai_flags;r
	*/
	char useless[184];
};

struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;		// effective user id
	uint32_t cr_ruid;		// real user id
	uint32_t useless2;
	uint32_t useless3;
	uint32_t cr_rgid;		// real group id
	uint32_t useless4;
	void *useless5;
	void *useless6;
	void *cr_prison;		// jail(2)
	void *useless7;
	uint32_t useless8;
	void *useless9[2];
	void *useless10;
	struct auditinfo_addr useless11;
	uint32_t *cr_groups;	// groups
	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
	void *fd_rdir;
	void *fd_jdir;
};

struct proc {
	char useless[64];
	struct ucred *p_ucred;
	struct filedesc *p_fd;
};

struct thread {
	void *useless;
	struct proc *td_proc;
};

struct kpayload_get_fw_version_info {
	uint64_t uaddr;
};

struct kpayload_get_fw_version_args {
	void* syscall_handler;
	struct kpayload_get_fw_version_info* kpayload_get_fw_version_info;
};

struct kpayload_jailbreak_info {
	uint64_t fw_version;
};

struct kpayload_jailbreak_args {
	void* syscall_handler;
	struct kpayload_jailbreak_info* kpayload_jailbreak_info;
};

struct kpayload_get_kbase_info {
	uint64_t fw_version;
	uint64_t uaddr;
};

struct kpayload_get_kbase_args {
	void* syscall_handler;
	struct kpayload_get_kbase_info* kpayload_get_kbase_info;
};

struct kpayload_kernel_dumper_info {
	uint64_t fw_version;
	uint64_t uaddr;
	uint64_t kaddr;
	size_t size;
};

struct kpayload_kernel_dumper_args {
	void* syscall_handler;
	struct kpayload_kernel_dumper_info* kpayload_kernel_dumper_info;
};

uint64_t get_fw_version(void);
int jailbreak(uint64_t fw_version);
uint64_t get_kernel_base(uint64_t fw_version);
uint64_t dump_kernel(uint64_t fw_version, uint64_t kaddr, uint64_t* dump, size_t size);

#endif
