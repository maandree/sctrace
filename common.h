/* See LICENSE file for copyright and license details. */
#if !defined __x86_64__ || defined __IPL32__
# error "This program is only implemented for x86-64"
#endif

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Constants used in system calls */
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "arg.h"
#include "list-errnos.h"


#ifndef ERESTARTSYS
# define ERESTARTSYS    512
# define ALSO_ERESTARTSYS
#endif
#ifndef ERESTARTNOINTR
# define ERESTARTNOINTR 513
# define ALSO_ERESTARTNOINTR
#endif
#ifndef ERESTARTNOHAND
# define ERESTARTNOHAND 514
# define ALSO_ERESTARTNOHAND
#endif
#ifndef ERESTART_RESTARTBLOCK
# define ERESTART_RESTARTBLOCK 516
# define ALSO_ERESTART_RESTARTBLOCK
#endif


enum type {
	Unknown,
	Void,
	Int,
	UInt,
	OInt,
	XInt,
	Long,
	ULong,
	OLong,
	XLong,
	LLong,
	ULLong,
	OLLong,
	XLLong,
	Ptr
};

enum state {
	Normal,
	Syscall,
	ForkChild,
	VforkChild,
	ForkParent,
	VforkParent,
	Exec
};

struct process {
	pid_t pid;
	struct process *next;
	struct process *prev;
	enum state state;

	/* Syscall data */
	unsigned long long int scall;
	unsigned long long int args[6];
	unsigned long long int ret;
	enum type ret_type;

	/* vfork(2) data */
	struct process *continue_on_exit;
	struct process *vfork_waiting_on;
};


/* consts.c */
const char *get_errno_name(int err);

/* memory.c */
char *get_string(pid_t pid, unsigned long int addr, size_t *lenp, const char **errorp);
int get_struct(pid_t pid, unsigned long int addr, void *out, size_t size, const char **errorp);
char *get_memory(pid_t pid, unsigned long int addr, size_t n, const char **errorp);
char *escape_memory(char *str, size_t m);

/* print.c */
void print_systemcall(struct process *proc);
void print_systemcall_exit(struct process *proc);

/* process.c */
void init_process_list(void);
struct process *find_process(pid_t pid);
struct process *add_process(pid_t pid, unsigned long int trace_options);
void remove_process(struct process *proc);

/* util.c */
void set_trace_output(FILE *fp);
void tprintf(struct process *proc, const char *fmt, ...);
_Noreturn void eprintf(const char *fmt, ...);
