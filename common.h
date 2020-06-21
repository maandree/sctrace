/* See LICENSE file for copyright and license details. */
#include <asm/unistd.h>
#include <sys/uio.h>
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

#if defined(__clang__)
# define FALL_THROUGH __attribute__((fallthrough));
#else
# define FALL_THROUGH
#endif

#if defined(__clang__)
# pragma clang diagnostic ignored "-Wdisabled-macro-expansion"
# pragma clang diagnostic ignored "-Wpadded"
#elif defined(__GNUC__)
# pragma GCC diagnostic ignored "-Wpadded"
# pragma GCC diagnostic ignored "-Wsuggest-attribute=pure"
# pragma GCC diagnostic ignored "-Wsuggest-attribute=format"
#endif

#if defined(__linux__)
# include "linux/os.h"
#else
# error "This program is only implemented for Linux"
#endif

/* #define signals that may appear in list-signums.h but may be missing in <signalh> */
#if !defined(SIGCLD) && defined(SIGCHLD)
# define SIGCLD SIGCHLD
#endif

#include "arg.h"
#include "list-errnos.h"
#include "list-signums.h"


struct process;

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
	CloneChild,
	ForkChild,
	VforkChild,
	CloneParent,
	ForkParent,
	VforkParent,
	Exec
};

struct output {
	int ells;
	char fmt;
	unsigned long long int size;
	void (*func)(struct process *, size_t);
};

struct process {
	pid_t pid;
	pid_t thread_leader;
	struct process *next;
	struct process *prev;
	enum state state;
	int silent_until_execed; /* 2 until exec, 1 until "= 0", 0 afterwards */

	/* Syscall data */
	unsigned long long int scall;
	unsigned long long int args[6];
	unsigned long long int ret;
	enum type ret_type;
	struct output outputs[6];
	/* multiarch support */
	unsigned long long int scall_xor;
	int long_is_int;
	int ptr_is_int;
	int mode;

	/* vfork(2) data */
	struct process *continue_on_exit;
	struct process *vfork_waiting_on;
};


/* consts.c */
const char *get_errno_name(int err);
const char *get_signum_name(int sig);

/* memory.c */
char *get_string(pid_t pid, unsigned long int addr, size_t *lenp, const char **errorp);
int get_struct(pid_t pid, unsigned long int addr, void *out, size_t size, const char **errorp);
char *get_memory(pid_t pid, unsigned long int addr, size_t n, const char **errorp);
char *escape_memory(char *str, size_t m);
char *get_escaped_string(pid_t pid, unsigned long int addr, size_t *lenp, const char **errorp);
char *get_escaped_memory(pid_t pid, unsigned long int addr, size_t n, const char **errorp);

/* print.c */
void print_systemcall(struct process *proc);
void print_systemcall_exit(struct process *proc);

/* process.c */
void init_process_list(void);
struct process *find_process(pid_t pid);
struct process *add_process(pid_t pid, unsigned long int trace_options);
void remove_process(struct process *proc);

/* util.c */
void setup_trace_output(FILE *fp, int multiprocess);
void tprintf(struct process *proc, const char *fmt, ...);
void weprintf(const char *fmt, ...);
#define eprintf(...) (weprintf(__VA_ARGS__), exit(1))
#define eprintf_and_kill(PID, ...) (weprintf(__VA_ARGS__), kill((PID), SIGKILL), exit(1))
FILE *xfopen(const char *file, const char *mode);
