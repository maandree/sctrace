/* See LICENSE file for copyright and license details. */
#include "common.h"


static FILE *trace_fp;
static char last_char = '\n';
static pid_t last_pid = 0;


void
set_trace_output(FILE *fp)
{
	trace_fp = fp;
}


void
tprintf(struct process *proc, const char *fmt, ...)
{
	va_list ap;
	if (fmt[0] == '\n' && fmt[1]) {
		last_pid = 0;
		fmt = &fmt[1];
	}
	if (last_char == '\n')
		fprintf(trace_fp, "[%ju] ", (uintmax_t)proc->pid);
	else if (proc->pid != last_pid)
		fprintf(trace_fp, "\n[%ju] ", (uintmax_t)proc->pid);
	va_start(ap, fmt);
	vfprintf(trace_fp, fmt, ap);
	last_pid = proc->pid;
	last_char = strchr(fmt, '\0')[-1];
	va_end(ap);
}


_Noreturn void
eprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "%s%s: ", last_char == '\n' ? "" : "\n", argv0);
	vfprintf(stderr, fmt, ap);
	switch (strchr(fmt, '\0')[-1]) {
	case ':':
		fprintf(stderr, " %s\n", strerror(errno));
		break;
	case '\n':
		break;
	default:
		fprintf(stderr, "\n");
		break;
	}
	va_end(ap);
	exit(1);
}
