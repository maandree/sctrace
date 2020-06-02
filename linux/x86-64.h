/* See LICENSE file for copyright and license details. */
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
#define SYSCALL_RET_REG rax

enum {
      x86_64 = 0,
      x32,
      i386
};

#define CHECK_ARCHITECTURE(proc, regsp)\
	do {\
		struct iovec iov = {\
			.iov_base = (regsp),\
			.iov_len = sizeof(*(regsp)),\
		};\
		if (ptrace(PTRACE_GETREGSET, (proc)->pid, NT_PRSTATUS, &iov)) {\
			eprintf("ptrace PTRACE_GETREGSET %ju NT_PRSTATUS {.iov_base=<buffer>, .iov_len=%zu}:",\
			        (uintmax_t)(proc)->pid, sizeof(*(regsp)));\
		} else if (iov.iov_len != sizeof(*(regsp))) {\
			if ((proc)->mode != i386) {\
				(proc)->mode = i386;\
				(proc)->long_is_int = 1;\
				(proc)->ptr_is_int = 1;\
				(proc)->scall_xor = 0;\
				tprintf(proc, "Process is running in i386 mode, this is not yet supported\n"); /* TODO */\
				exit(1);\
			}\
		} else if ((proc)->scall & __X32_SYSCALL_BIT) {\
			if ((proc)->mode != x32) {\
				(proc)->mode = x32;\
				(proc)->long_is_int = 0;\
				(proc)->ptr_is_int = 1;\
				(proc)->scall_xor = __X32_SYSCALL_BIT;\
				tprintf(proc, "Process is running in x32 mode (support is untested)\n");\
			}\
		} else {\
			if ((proc)->mode != x86_64) {\
				(proc)->mode = x86_64;\
				(proc)->long_is_int = 0;\
				(proc)->ptr_is_int = 0;\
				(proc)->scall_xor = 0;\
				tprintf(proc, "Process is running in x86-64 mode\n");\
			}\
		}\
	} while (0)

#define GET_SYSCALL_ARGUMENTS(proc, regsp)\
	do {\
		if ((proc)->mode != i386) {\
			(proc)->args[0] = (regsp)->rdi;\
			(proc)->args[1] = (regsp)->rsi;\
			(proc)->args[2] = (regsp)->rdx;\
			(proc)->args[3] = (regsp)->r10;\
			(proc)->args[4] = (regsp)->r8;\
			(proc)->args[5] = (regsp)->r9;\
		} else {\
			(proc)->args[0] = ((const struct i386_user_regs_struct *)(regsp))->ebx;\
			(proc)->args[1] = ((const struct i386_user_regs_struct *)(regsp))->ecx;\
			(proc)->args[2] = ((const struct i386_user_regs_struct *)(regsp))->edx;\
			(proc)->args[3] = ((const struct i386_user_regs_struct *)(regsp))->esi;\
			(proc)->args[4] = ((const struct i386_user_regs_struct *)(regsp))->edi;\
			(proc)->args[5] = ((const struct i386_user_regs_struct *)(regsp))->ebp;\
		}\
	} while (0)
