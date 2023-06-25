/* See LICENSE file for copyright and license details. */
#include "common.h"


char *argv0;
static unsigned long int trace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT;


_Noreturn static void
usage(void)
{
	fprintf(stderr, "usage: %s [-a byte-count] [-o trace-output-file] [-ft]"
	                " (command | -0 command argv0) [argument] ...\n", argv0);
	exit(1);
}


static void
fetch_systemcall(struct process *proc, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, proc->pid, REGARGS(NULL, regs)))
		eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
	proc->scall = regs->SYSCALL_NUM_REG;
#ifdef CHECK_ARCHITECTURE
	CHECK_ARCHITECTURE(proc, regs);
	proc->scall ^= proc->scall_xor;
#endif
	GET_SYSCALL_ARGUMENTS(proc, regs);
	memset(proc->save, 0, sizeof(proc->save));
}


static void
fetch_systemcall_result(struct process *proc, struct user_regs_struct *regs)
{
	if (ptrace(PTRACE_GETREGS, proc->pid, REGARGS(NULL, regs)))
		eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
	proc->ret = regs->SYSCALL_RET_REG;
}


static void
enter_systemcall(struct process *proc)
{
	if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
		eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
}


static void
leave_systemcall(struct process *proc)
{
	if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
		eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
}


static void
restart_systemcall(struct process *proc, int sig)
{
	if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, sig))
		eprintf("ptrace PTRACE_SYSCALL %ju NULL %i:", (uintmax_t)proc->pid, sig);
}


static void
vfork_start(struct process *proc)
{
	tprintf(proc, "\nProcess stopped by vfork until child exits or exec(2)s\n");
}


static void
vfork_done(struct process *proc, const char *reason)
{
	tprintf(proc, "\nProcess continues due to %s of vfork child\n", reason);
}


static void
process_exiting(struct process *proc, int status)
{
	(void) proc;
	(void) status;
}


static void
process_exited(struct process *proc, int status)
{
	if (WIFEXITED(status)) {
		tprintf(proc, "\nProcess exited%s with value %i%s\n",
		        proc->state == Zombie ? "" : ", without knell",
		        WEXITSTATUS(status), WCOREDUMP(status) ? ", core dumped" : "");
	} else {
		tprintf(proc, "\nProcess terminated%s by signal %i (%s: %s)%s\n",
		        proc->state == Zombie ? "" : ", without knell",
		        WTERMSIG(status), get_signum_name(WTERMSIG(status)),
		        strsignal(WTERMSIG(status)), WCOREDUMP(status) ? ", core dumped" : "");
	}
}


static void
process_signalled(struct process *proc, int sig, int stopped)
{
	tprintf(proc, "\nProcess %s signal %i (%s: %s)\n",
	        stopped ? "stopped by" : "received",
	        sig, get_signum_name(sig), strsignal(sig));
}


static void
process_continued(struct process *proc, int status)
{
	tprintf(proc, "\n%s continued, presumably by signal %i (SIGCONT: %s)\n",
	        proc->state == Zombie ? "Zombie process" : "Process", SIGCONT, strsignal(SIGCONT));
	(void) status;
}


static void
restart_process(struct process *proc, int cmd, int sig)
{
	if (ptrace(cmd, proc->pid, NULL, sig)) {
		eprintf("ptrace %s %ju NULL %i:",
		        cmd == PTRACE_CONT ? "PTRACE_CONT" :
		        cmd == PTRACE_LISTEN ? "PTRACE_LISTN" :
		        cmd == PTRACE_SYSEMU ? "PTRACE_SYSEMU" :
		        cmd == PTRACE_SYSCALL ? "PTRACE_SYSCALL" : "???",
		        (uintmax_t)proc->pid, sig);
	}
}


static void
process_created(struct process *proc, struct process *parent)
{
	tprintf(proc, "\nTracing new process with parent %ju\n", (uintmax_t)parent->pid);
	tprintf(proc, "= 0\n");
}


static void
zombie_stopped(struct process *proc, int status)
{
	tprintf(proc, "\nReceived unexpected event on zombie process\n");
	(void) status;
}


static void
handle_syscall(struct process *proc)
{
	struct user_regs_struct regs;

	switch ((int)proc->state) {
	case UserSpace:
		fetch_systemcall(proc, &regs);
		print_systemcall(proc);
		enter_systemcall(proc);
		proc->state = KernelSpace;
		break;

	case KernelSpace:
		fetch_systemcall_result(proc, &regs);
		if (!proc->ignore_until_execed)
			print_systemcall_exit(proc);
		else
			proc->ignore_until_execed -= (proc->ignore_until_execed == 1);
		leave_systemcall(proc);
		proc->state = UserSpace;
		break;

	default:
		abort();
	}
}


static unsigned long int
get_event_msg(struct process *proc)
{
	unsigned long int event;
	if (ptrace(PTRACE_GETEVENTMSG, proc->pid, NULL, &event))
		eprintf("ptrace PTRACE_GETEVENTMSG %ju NULL <buffer>:", (uintmax_t)proc->pid);
	return event;
}


static void
handle_event(struct process *proc, int status)
{
	struct process *proc2;
	int sig = WSTOPSIG(status);
	int trace_event = status >> 16;
	switch (trace_event) {

	case PTRACE_EVENT_VFORK:
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_CLONE:
		proc2 = add_process((pid_t)get_event_msg(proc), trace_event == PTRACE_EVENT_CLONE ? proc->pid : 0, trace_options);
		if (trace_event == PTRACE_EVENT_VFORK) {
			vfork_start(proc);
			proc2->continue_on_exit = proc;
			proc->vfork_waiting_on = proc2;
		}
		process_created(proc2, proc);
		restart_systemcall(proc2, 0);
		restart_systemcall(proc, 0);
		break;

	case PTRACE_EVENT_EXEC:
		proc->ignore_until_execed -= (proc->ignore_until_execed == 2);
		restart_systemcall(proc, 0);
		proc2 = proc->continue_on_exit;
		if (proc2) {
			proc->continue_on_exit = NULL;
			proc2->vfork_waiting_on = NULL;
			vfork_done(proc2, "exec(2)");
		}
		break;

	case PTRACE_EVENT_STOP:
		switch (sig) {
		case SIGSTOP:
		case SIGTSTP:
		case SIGTTIN:
		case SIGTTOU:
			process_signalled(proc, sig, 1);
			restart_process(proc, PTRACE_LISTEN, 0);
			break;
		default:
			tprintf(proc, "\nTRACE_EVENT_STOP with signal %i (%s: %s)\n",
				WTERMSIG(status), get_signum_name(WTERMSIG(status)),
				strsignal(WTERMSIG(status)));
			restart_systemcall(proc, 0);
			break;
		}
		break;

	case PTRACE_EVENT_EXIT:
		process_exiting(proc, (int)get_event_msg(proc));
		proc->state = Zombie;
		restart_process(proc, PTRACE_CONT, 0);
		break;

	case PTRACE_EVENT_VFORK_DONE:
		restart_systemcall(proc, 0);
		break;

	default:
		abort();

	case 0:
		process_signalled(proc, sig, 0);
		restart_systemcall(proc, sig);
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
	char *arg;
	struct process *proc;
	struct sigaction sa;
	sigset_t sm;

	/* TODO add option to trace signals with siginfo (-s) */
	ARGBEGIN {
	case '0':
		with_argv0 = 1;
		break;
	case 'a':
		arg = EARGF(usage());
		if (!strcmp(arg, "inf")) {
			abbreviate_memory = SIZE_MAX;
			break;
		}
		if (!isdigit(arg[0]))
			usage();
		errno = 0;
		abbreviate_memory = (size_t)strtoul(arg, &arg, 10);
		if ((errno && errno != ERANGE) || *arg)
			usage();
		break;
	case 'o':
		if (outfile)
			usage();
		outfile = EARGF(usage());
		break;
	case 'f':
		trace_options |= PTRACE_O_TRACEFORK;
		trace_options |= PTRACE_O_TRACEVFORK;
		trace_options |= PTRACE_O_TRACEVFORKDONE;
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

	if (prctl(PR_SET_CHILD_SUBREAPER, 1))
		weprintf("prctl PR_SET_CHILD_SUBREAPER 1:");

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
	proc = add_process(orig_pid, 0, trace_options);
	proc->ignore_until_execed = 2;
	restart_systemcall(proc, 0);

	for (;;) {
		pid = waitpid(-1, &status, __WALL | WCONTINUED); /* TODO WCONTINUED should require waitid */
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
			if (proc->state == Zombie)
				zombie_stopped(proc, status);
			else if (WSTOPSIG(status) == (SIGTRAP | 0x80))
				handle_syscall(proc);
			else
				handle_event(proc, status);
		} else if (WIFCONTINUED(status)) {
			process_continued(proc, status);
		} else {
			if (pid == orig_pid)
				exit_code = status;
			process_exited(proc, status);
			if (proc->continue_on_exit)
				vfork_done(proc->continue_on_exit, WIFEXITED(status) ? "exit" : "abnormal termination");
			remove_process(proc);
		}

		fflush(outfp);
	}

	fflush(outfp);
	if (outfp != stderr)
		fclose(outfp);

	weprintf("Copying exit from %s\n", multiprocess ? "original tracee" : "tracee");
	if (WIFSIGNALED(exit_code)) {
		prctl(PR_SET_DUMPABLE, 0);
		exit_code = WTERMSIG(exit_code);
		raise(exit_code);
		return exit_code + 128;
	}
	return WEXITSTATUS(exit_code);
}
