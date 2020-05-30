/* See LICENSE file for copyright and license details. */
#include "common.h"


char *argv0;


static void
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
		/* Get systemcall arguments */
		if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &regs))
			eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
		proc->scall = regs.orig_rax;
		proc->args[0] = regs.rdi;
		proc->args[1] = regs.rsi;
		proc->args[2] = regs.rdx;
		proc->args[3] = regs.r10;
		proc->args[4] = regs.r8;
		proc->args[5] = regs.r9;

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
		if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &regs))
			eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);

		/* Get or set return */
		if (proc->state == Syscall) {
			proc->ret = regs.rax;
		} else {
			regs.rax = proc->ret;
			if (ptrace(PTRACE_SETREGS, proc->pid, NULL, &regs))
				eprintf("ptrace PTRACE_SETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
			if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
				eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
		}

		/* Print system call result */
		print_systemcall_exit(proc);

		/* Make process continue and stop at next syscall */
		if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
			eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);

		proc->state = Normal;
		break;

	case Exec:
		if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
			eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)proc->pid);
		proc->state = Normal;
		break;

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


int
main(int argc, char **argv)
{
	pid_t pid, orig_pid;
	long int tmp;
	char *outfile = NULL;
	FILE *outfp = stderr;
	const char *num = NULL;
	int status, exit_value = 0, trace_event, with_argv0 = 0, multiprocess = 0;
	unsigned long int trace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;
	struct process *proc, *proc2;
	unsigned long int event;

	/* TODO add option to trace signals with siginfo (-s) */
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

	init_process_list();

	/* Start program to trace */
	pid = fork();
	switch (pid) {
	case -1:
		eprintf("fork:");
		return 1;
	case 0:
		if (ptrace(PTRACE_TRACEME, 0, NULL, 0)) {
			eprintf("ptrace PTRACE_TRACEME 0 NULL 0:");
			return 1;
		}
		/* exec will block until parent attaches */
		execvp(*argv, &argv[with_argv0]);
		kill(getppid(), SIGKILL);
		eprintf("execvp %s:", *argv);
	default:
		orig_pid = pid;
		add_process(pid, trace_options);
		break;
	}

	/* Open trace output file */
	if (outfile) {
		if (!strncmp(outfile, "/dev/fd/", sizeof("/dev/fd/") - 1))
			num = &outfile[sizeof("/dev/fd/") - 1];
		else if (!strncmp(outfile, "/proc/self/fd/", sizeof("/proc/self/fd/") - 1))
			num = &outfile[sizeof("/proc/self/fd/") - 1];
		else if (!strcmp(outfile, "/dev/stdin"))
			num = "0";
		else if (!strcmp(outfile, "/dev/stdout"))
			num = "1";
		else if (!strcmp(outfile, "/dev/stderr"))
			num = "2";
		if (num && isdigit(*num)) {
			errno = 0;
			tmp = strtol(num, (void *)&num, 10);
			if (!errno && tmp >= 0 &&
#if INT_MAX < LONG_MAX
			    tmp < INT_MAX &&
#endif
			    !*num) {
				outfp = fdopen((int)tmp, "wb");
				if (!outfp) {
					eprintf("fdopen %li wb:", tmp);
					return 1;
				}
				goto have_outfp;
			}
		}
		outfp = fopen(outfile, "wb");
		if (!outfp) {
			eprintf("fopen %s wb:", outfile);
			return 1;
		}
	}

have_outfp:
	setup_trace_output(outfp, multiprocess);

	for (;;) {
		pid = wait(&status);
		if (pid < 0) {
			if (errno == ECHILD)
				return exit_value;
			eprintf("wait <buffer>:");
			return 1;
		}

		proc = find_process(pid);
		if (!proc)
			continue;

		if (WIFEXITED(status)) {
			if (pid == orig_pid)
				exit_value = WEXITSTATUS(status);
			tprintf(proc, "\nProcess exited with value %i\n", WEXITSTATUS(status));
			proc2 = proc->continue_on_exit;
			remove_process(proc);
			if (proc2) {
				tprintf(proc2, "\nProcess continues due to exit of vfork child\n");
				handle_syscall(proc2);
			}

		} else if (WIFSIGNALED(status)) {
			tprintf(proc, "\nProcess terminated by signal %i (%s: %s)\n", WTERMSIG(status),
			        get_signum_name(WTERMSIG(status)), strsignal(WTERMSIG(status)));

		} else if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
				handle_syscall(proc);
			} else if (WSTOPSIG(status) == SIGTRAP) {
				trace_event = ((status >> 8) ^ SIGTRAP) >> 8;
				switch (trace_event) {

				case PTRACE_EVENT_VFORK:
					tprintf(proc, "\nProcess stopped by vfork until child exits or exec(2)s\n");
					/* fall thought */
				case PTRACE_EVENT_FORK:
				case PTRACE_EVENT_CLONE:
					if (ptrace(PTRACE_GETEVENTMSG, proc->pid, NULL, &event))
						eprintf("ptrace PTRACE_GETEVENTMSG %ju NULL <buffer>:", (uintmax_t)proc->pid);
					proc2 = add_process((pid_t)event, trace_options);
					if (trace_event == PTRACE_EVENT_CLONE)
						proc2->thread_group_leader = proc->pid;
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

				default:
					goto print_signal;
				}
			} else {
			print_signal:
				tprintf(proc, "\nProcess received signal %i (%s: %s)\n", WSTOPSIG(status),
				        get_signum_name(WSTOPSIG(status)), strsignal(WSTOPSIG(status)));
				/* TODO handle signals properly (siginfo?, SIGSTOP &c does not stop the process) */
				if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, WSTOPSIG(status)))
					eprintf("ptrace PTRACE_SYSCALL %ju NULL %i:", (uintmax_t)proc->pid, WSTOPSIG(status));
			}

		} else if (WIFCONTINUED(status)) {
			tprintf(proc, "\nProcess continued\n", (uintmax_t)pid);
		}
	}

	fclose(outfp);
	return 0;
}
