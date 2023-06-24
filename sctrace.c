/* See LICENSE file for copyright and license details. */
#include "common.h"


char *argv0;
static unsigned long int trace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;


_Noreturn static void
usage(void)
{
	fprintf(stderr, "usage: %s [-o trace-output-file] [-ft] (command | -0 command argv0) [argument] ...\n", argv0);
	exit(1);
}


static void
handle_syscall(struct process *proc)
{
	struct user_regs_struct regs;

	switch ((int)proc->state) {
	default:
		/* Get system call arguments */
		if (ptrace(PTRACE_GETREGS, proc->pid, REGARGS(NULL, &regs)))
			eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
		proc->scall = regs.SYSCALL_NUM_REG;
#ifdef CHECK_ARCHITECTURE
		CHECK_ARCHITECTURE(proc, &regs);
		proc->scall ^= proc->scall_xor;
#endif
		GET_SYSCALL_ARGUMENTS(proc, &regs);

		/* Print system call */
		print_systemcall(proc);

		/* Run system call */
		if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
			eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);

		proc->state = Syscall;
		break;

	case Syscall:
	case CloneParent:
	case ForkParent:
		/* Get system call result */
		if (ptrace(PTRACE_GETREGS, proc->pid, REGARGS(NULL, &regs)))
			eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);

		/* Get or set return */
		if (proc->state == Syscall) {
			proc->ret = regs.SYSCALL_RET_REG;
		} else {
			regs.SYSCALL_RET_REG = proc->ret;
			if (ptrace(PTRACE_SETREGS, proc->pid, REGARGS(NULL, &regs)))
				eprintf("ptrace PTRACE_SETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
			if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
				eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
		}

		/* Print system call result */
		print_systemcall_exit(proc);

		proc->silent_until_execed -= (proc->silent_until_execed == 1);

		/* Make process continue and stop at next syscall */
		if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
			eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);

		proc->state = Normal;
		break;

	case Exec:
		proc->silent_until_execed -= (proc->silent_until_execed == 2);
		FALL_THROUGH
		/* fall through */
	case VforkParent:
		if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
			eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
		proc->state = Syscall;
		break;

	case CloneChild:
	case ForkChild:
	case VforkChild:
		tprintf(proc, "= 0\n");
		proc->state = Normal;
		break;
	}
}


static void
handle_event(struct process *proc, int status)
{
	int trace_event, sig;
	unsigned long int event;
	struct process *proc2;

	sig = WSTOPSIG(status);
	trace_event = status >> 16;
	switch (trace_event) {

	case PTRACE_EVENT_VFORK:
		tprintf(proc, "\nProcess stopped by vfork until child exits or exec(2)s\n");
		FALL_THROUGH
		/* fall through */
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_CLONE:
		if (ptrace(PTRACE_GETEVENTMSG, proc->pid, NULL, &event))
			eprintf("ptrace PTRACE_GETEVENTMSG %ju NULL <buffer>:", (uintmax_t)proc->pid);
		proc2 = add_process((pid_t)event, trace_options);
		if (trace_event == PTRACE_EVENT_CLONE)
			proc2->thread_leader = proc->pid;
		proc->ret = event;
		if (trace_event == PTRACE_EVENT_VFORK) {
			proc2->continue_on_exit = proc;
			proc->vfork_waiting_on = proc2;
			proc->state = VforkParent;
		} else {
			proc->state = trace_event == PTRACE_EVENT_CLONE ? CloneParent : ForkParent;
			handle_syscall(proc);
		}
		tprintf(proc2, "\nTracing new process\n");
		proc2->state = trace_event == PTRACE_EVENT_FORK ? ForkChild :
			trace_event == PTRACE_EVENT_VFORK ? VforkChild : CloneChild;
		handle_syscall(proc2);
		break;

	case PTRACE_EVENT_EXEC:
		proc->state = Exec;
		handle_syscall(proc);
		proc2 = proc->continue_on_exit;
		if (proc2) {
			proc->continue_on_exit = NULL;
			proc2->vfork_waiting_on = NULL;
			tprintf(proc2, "\nProcess continues due to exec(2) of vfork child\n");
			handle_syscall(proc2);
		}
		break;

	case PTRACE_EVENT_STOP:
		switch (sig) {
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
		stop_signal:
			tprintf(proc, "\nProcess stopped by signal %i (%s: %s)\n", sig, get_signum_name(sig), strsignal(sig));
			if (ptrace(PTRACE_LISTEN, proc->pid, NULL, 0))
				eprintf("ptrace PTRACE_LISTEN %ju NULL 0:", (uintmax_t)proc->pid);
			break;
		default:
			if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
				eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
			break;
		}
		break;

	default:
		abort();

	case 0:
		if (ptrace(PTRACE_GETSIGINFO, proc->pid, 0, &(siginfo_t){0}))
			goto stop_signal;
		tprintf(proc, "\nProcess received signal %i (%s: %s)\n", sig, get_signum_name(sig), strsignal(sig));
		if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, sig))
			eprintf("ptrace PTRACE_SYSCALL %ju NULL %i:", (uintmax_t)proc->pid, sig);
		break;
	}
}


int
main(int argc, char **argv)
{
	pid_t pid, orig_pid;
	char *outfile = NULL;
	FILE *outfp = stderr;
	int status, exit_code = 0, with_argv0 = 0, multiprocess = 0, i;
	struct process *proc, *proc2;
	struct sigaction sa;
	sigset_t sm;

	/* TODO add option to trace signals with siginfo (-s) */
	/* TODO add option to truncate long syscall arguments and outputs (-a)
	 *      This should be useful if your program does a lot of I/O */
	ARGBEGIN {
	case '0':
		with_argv0 = 1;
		break;
	case 'o':
		if (outfile)
			usage();
		outfile = EARGF(usage());
		break;
	case 'f':
		trace_options |= PTRACE_O_TRACEFORK;
		trace_options |= PTRACE_O_TRACEVFORK;
		FALL_THROUGH
		/* fall through */
	case 't':
		trace_options |= PTRACE_O_TRACECLONE;
		multiprocess = 1;
		break;
	default:
		usage();
	} ARGEND;
	if (!argc)
		usage();

	orig_pid = fork();
	switch (orig_pid) {
	case -1:
		eprintf("fork:");
	case 0:
		if (raise(SIGSTOP))
			eprintf_and_kill(getppid(), "raise SIGSTOP:");
		execvp(*argv, &argv[with_argv0]);
		eprintf_and_kill(getppid(), "execvp %s:", *argv);
	default:
		break;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	for (i = 1; i <= _NSIG; i++)
		sigaction(i, &sa, NULL);
	sigemptyset(&sm);
	if (sigprocmask(SIG_SETMASK, &sm, NULL))
		eprintf_and_kill(orig_pid, "sigprocmask SIG_SETMASK <empty sigset_t> NULL:");
	outfp = outfile ? xfopen(outfile, "wb") : stderr;
	setup_trace_output(outfp, multiprocess);
	init_process_list();
	add_process(orig_pid, trace_options)->silent_until_execed = 2;

	for (;;) {
		pid = waitpid(-1, &status, __WALL | WCONTINUED);
		if (pid < 0) {
			if (errno == ECHILD)
				break;
			if (errno == EINTR)
				continue;
			eprintf("waitpid -1 <buffer> __WALL|WCONTINUED:");
		}

		proc = find_process(pid);
		if (!proc)
			continue;

		if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) == (SIGTRAP | 0x80))
				handle_syscall(proc);
			else
				handle_event(proc, status);
		} else if (WIFCONTINUED(status)) {
			tprintf(proc, "\nProcess continued, presumably by signal %i (SIGCONT: %s)\n", SIGCONT, strsignal(SIGCONT));
		} else {
			if (pid == orig_pid)
				exit_code = status;
			if (WIFEXITED(status)) {
				tprintf(proc, "\nProcess exited with value %i%s\n", WEXITSTATUS(status),
					WCOREDUMP(status) ? ", core dumped" : "");
			} else {
				tprintf(proc, "\nProcess terminated by signal %i (%s: %s)%s\n", WTERMSIG(status),
					get_signum_name(WTERMSIG(status)), strsignal(WTERMSIG(status)),
					WCOREDUMP(status) ? ", core dumped" : "");
			}
			proc2 = proc->continue_on_exit;
			remove_process(proc);
			if (proc2) {
				if (WIFEXITED(status))
					tprintf(proc2, "\nProcess continues due to exit of vfork child\n");
				else
					tprintf(proc2, "\nProcess continues due to abnormal termination of vfork child\n");
				handle_syscall(proc2);
			}
		}

		fflush(outfp);
	}

	fflush(outfp);
	if (outfp != stderr)
		fclose(outfp);

	if (WIFSIGNALED(exit_code)) {
		exit_code = WTERMSIG(exit_code);
		raise(exit_code);
		return exit_code + 128;
	}
	return WEXITSTATUS(exit_code);
}
