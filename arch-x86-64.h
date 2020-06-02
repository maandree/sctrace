struct i386_user_regs_struct
{
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;
	uint32_t esi;
	uint32_t edi;
	uint32_t ebp;
	uint32_t eax;
	uint32_t xds;
	uint32_t xes;
	uint32_t xfs;
	uint32_t xgs;
	uint32_t orig_eax;
	uint32_t eip;
	uint32_t xcs;
	uint32_t eflags;
	uint32_t esp;
	uint32_t xss;
};

#define SYSCALL_NUM_REG orig_rax
#define SYSCALL_ARG1_REG rdi
#define SYSCALL_ARG2_REG rsi
#define SYSCALL_ARG3_REG rdx
#define SYSCALL_ARG4_REG r10
#define SYSCALL_ARG5_REG r8
#define SYSCALL_ARG6_REG r9
#define SYSCALL_RET_REG rax
