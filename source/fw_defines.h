#ifndef __FW_DEFINES_H__
#define __FW_DEFINES_H__

							// order: (to avoid kernel panic by reading not allocated memory)
#define	KERN_405_XFAST_SYSCALL		0x30EB30	// #3
#define	KERN_455_XFAST_SYSCALL		0x3095D0	// #2
#define	KERN_501_XFAST_SYSCALL		0x1C0		// #1
#define	KERN_505_XFAST_SYSCALL		0x1C0		// #1

#define KERN_405_PRISON_0		0xF26010
#define KERN_455_PRISON_0		0x10399B0
#define KERN_501_PRISON_0		0x10986A0
#define KERN_505_PRISON_0		0x10986A0

#define KERN_405_ROOTVNODE		0x206D250
#define KERN_455_ROOTVNODE		0x21AFA30
#define KERN_501_ROOTVNODE		0x22C19F0
#define KERN_505_ROOTVNODE		0x22C1A70

#define KERN_405_PRINTF			0x347580
#define KERN_455_PRINTF			0x17F30
#define KERN_501_PRINTF			0x435C70
#define KERN_505_PRINTF			0x436040

#define KERN_405_COPYIN			0x286DF0

#define KERN_405_COPYOUT		0x286D70
#define KERN_455_COPYOUT		0x14A7B0
#define KERN_501_COPYOUT		0x1EA520
#define KERN_505_COPYOUT		0x1EA630

#define KERN_405_BZERO			0x286C30
#define KERN_455_BZERO			0x14A570
#define KERN_501_BZERO			0x1EA360
#define KERN_505_BZERO			0x1EA510


#endif