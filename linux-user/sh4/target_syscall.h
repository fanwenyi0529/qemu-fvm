#ifndef SH4_TARGET_SYSCALL_H
#define SH4_TARGET_SYSCALL_H

struct target_pt_regs {
        unsigned long regs[16];
        uintptr_t pc;
        unsigned long pr;
        unsigned long sr;
        unsigned long gbr;
        unsigned long mach;
        unsigned long macl;
        long tra;
};

#define UNAME_MACHINE "sh4"
#define UNAME_MINIMUM_RELEASE "2.6.32"

#define TARGET_MINSIGSTKSZ 2048
#define TARGET_MLOCKALL_MCL_CURRENT 1
#define TARGET_MLOCKALL_MCL_FUTURE  2

#endif /* SH4_TARGET_SYSCALL_H */
