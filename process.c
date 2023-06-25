/* See LICENSE file for copyright and license details. */
#include "common.h"


static struct process head;
static struct process tail;


void
init_process_list(void)
{
	head.next = &tail;
	tail.prev = &head;
}


struct process *
find_process(pid_t pid)
{
	struct process *p;
	for (p = head.next; p->next; p = p->next)
		if (p->pid == pid)
			return p;
	return NULL;
}


struct process *
add_process(pid_t pid, pid_t leader, unsigned long int trace_options)
{
	struct process *proc;
	int status, sig;

	proc = calloc(1, sizeof(*proc));
	if (!proc)
		eprintf("calloc: %s\n");
	proc->pid = pid;
	proc->thread_leader = leader;
	proc->next = &tail;
	proc->prev = tail.prev;
	proc->prev->next = proc;
	tail.prev = proc;

	if (!leader)
		leader = pid;

	while (waitpid(pid, &status, WUNTRACED) != pid) {
		if (errno == EINTR)
			continue;
		eprintf_and_kill(pid, "waitpid %ju <buffer> WSTOPPED:", (uintmax_t)pid);
	}

	sig = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
	if (sig == SIGSTOP) {
		if (ptrace(PTRACE_SEIZE, pid, NULL, trace_options))
			eprintf_and_kill(pid, "ptrace PTRACE_SEIZE %ju NULL ...:", (uintmax_t)pid);
		if (ptrace(PTRACE_INTERRUPT, pid, NULL, 0))
			eprintf_and_kill(pid, "ptrace PTRACE_INTERRUPT %ju NULL 0:", (uintmax_t)pid);
		if (tgkill(leader, pid, SIGCONT) < 0)
			eprintf_and_kill(pid, "tgkill %ju %ju SIGCONT:", (uintmax_t)leader, (uintmax_t)pid);
	} else if (sig == SIGTRAP && status & PTRACE_EVENT_STOP << 16) {
		if (ptrace(PTRACE_SETOPTIONS, pid, NULL, trace_options))
			eprintf_and_kill(pid, "ptrace PTRACE_SETOPTIONS %ju NULL ...:", (uintmax_t)pid);
	} else {
		eprintf_and_kill(pid, "unexpected return of waitpid %ju <buffer> WSTOPPED: %#x\n", (uintmax_t)pid, status);
	}

	return proc;
}


void
remove_process(struct process *proc)
{
 	proc->prev->next = proc->next;
	proc->next->prev = proc->prev;
	if (proc->vfork_waiting_on)
		proc->vfork_waiting_on->continue_on_exit = NULL;
	if (proc->continue_on_exit)
		proc->continue_on_exit->vfork_waiting_on = NULL;
	free(proc);
}
