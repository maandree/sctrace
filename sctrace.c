/* See LICENSE file for copyright and license details. */
#include "common.h"


char *argv0;


static void
usage(void)
{
	fprintf(stderr, "usage: %s [-f trace-output-file] [-CFV] command ...\n", argv0);
	exit(1);
}


static void
handle_syscall(struct process *proc)
{
	struct user_regs_struct regs;

	switch (proc->state) {
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
		/* Get system call result */
		if (ptrace(PTRACE_GETREGS, proc->pid, NULL, &regs))
			eprintf("ptrace PTRACE_GETREGS %ju NULL <buffer>:", (uintmax_t)proc->pid);
		proc->ret = regs.rax;

		/* Print system call result */
		print_systemcall_exit(proc);

		/* Make process continue and stop at next syscall */
		if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
			eprintf("ptrace PTRACE_SYSCALL %ju NULL 0", (uintmax_t)proc->pid);

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
	int status, exit_value = 0;
	unsigned long int trace_options = PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD;
	struct process *proc;
	unsigned long int event;

	/* TODO add support for exec */
	/* TODO add option to trace threads */
	/* TODO add option to trace vforks */
	/* TODO add option to trace signals */
	/* TODO add option to specify argv[0] */
	ARGBEGIN {
	case 'f':
		if (outfile)
			usage();
		outfile = EARGF(usage());
		break;
	case 'F':
		trace_options |= PTRACE_O_TRACEFORK;
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
		execvp(*argv, argv);
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
	set_trace_output(outfp);

	for (;;) {
		/* Wait for next syscall enter/exit */
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

		} else if (WIFSIGNALED(status)) {
			tprintf(proc, "\nProcess terminated by signal %i (%s)\n", WTERMSIG(status), strsignal(WTERMSIG(status)));
			/* TODO print signal name */

		} else if (WIFSTOPPED(status)) {
			if (WSTOPSIG(status) == (SIGTRAP | 0x80)) {
				handle_syscall(proc);
			} else if (WSTOPSIG(status) == SIGTRAP) {
				switch (((status >> 8) ^ SIGTRAP) >> 8) {

				case PTRACE_EVENT_FORK:
					if (ptrace(PTRACE_GETEVENTMSG, proc->pid, NULL, &event))
						eprintf("ptrace PTRACE_GETEVENTMSG %ju NULL <buffer>:", (uintmax_t)proc->pid);
					add_process((pid_t)event, trace_options);
					handle_syscall(proc);
					break;

				default:
					goto print_signal;
				}
			} else {
			print_signal:
				tprintf(proc, "\nProcess stopped by signal %i (%s)\n", WSTOPSIG(status), strsignal(WSTOPSIG(status)));
				/* TODO print signal name */
			}

		} else if (WIFCONTINUED(status)) {
			tprintf(proc, "\nProcess continued\n", (uintmax_t)pid);
		}
	}

	fclose(outfp);
	return 0;
}
