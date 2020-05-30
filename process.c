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
add_process(pid_t pid, int trace_options)
{
        struct process *proc;
	int saved_errno;
        proc = calloc(1, sizeof(*proc));
	if (!proc)
                eprintf("calloc: %s\n");
        proc->pid = pid;
	if (waitpid(pid, NULL, 0) < 0) {
		eprintf("waitpid <child> NULL 0:");
		kill(pid, SIGKILL);
		exit(1);
	}
	if (ptrace(PTRACE_SETOPTIONS, pid, 0, trace_options)) {
		saved_errno = errno;
		kill(pid, SIGKILL);
		errno = saved_errno;
		eprintf("ptrace PTRACE_SETOPTIONS %ju 0 ...:", (uintmax_t)pid);
	}
        if (ptrace(PTRACE_SYSCALL, proc->pid, NULL, 0))
                eprintf("ptrace PTRACE_SYSCALL %ju NULL 0:", (uintmax_t)pid);
        proc->next = &tail;
	proc->prev = tail.prev;
	proc->prev->next = proc;
	tail.prev = proc;
	return proc;
}


void
remove_process(struct process *proc)
{
 	proc->prev->next = proc->next;
	proc->next->prev = proc->prev;
	free(proc);
}
