/* See LICENSE file for copyright and license details. */
#include "common.h"


static FILE *trace_fp;
static char last_char = '\n';
static pid_t last_pid = 0;
static int multiproctrace;


void
setup_trace_output(FILE *fp, int multiprocess)
{
	multiproctrace = multiprocess;
	trace_fp = fp;
}


void
tprintf(struct process *proc, const char *fmt, ...)
{
	va_list ap;
	if (proc->silent_until_execed)
		return;
	if (fmt[0] == '\n' && fmt[1]) {
		last_pid = 0;
		if (multiproctrace || last_char == '\n')
			fmt = &fmt[1];
	}
	if (multiproctrace) {
		if (proc->thread_leader) {
			if (last_char == '\n')
				fprintf(trace_fp, "[%ju, %ju] ", (uintmax_t)proc->thread_leader, (uintmax_t)proc->pid);
			else if (proc->pid != last_pid)
				fprintf(trace_fp, "\n[%ju, %ju] ", (uintmax_t)proc->thread_leader, (uintmax_t)proc->pid);
		} else {
			if (last_char == '\n')
				fprintf(trace_fp, "[%ju] ", (uintmax_t)proc->pid);
			else if (proc->pid != last_pid)
				fprintf(trace_fp, "\n[%ju] ", (uintmax_t)proc->pid);
		}
	}
	va_start(ap, fmt);
	vfprintf(trace_fp, fmt, ap);
	last_pid = proc->pid;
	last_char = strchr(fmt, '\0')[-1];
	va_end(ap);
}


void
weprintf(const char *fmt, ...)
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
}


FILE *
xfopen(const char *file, const char *mode)
{
	FILE *ret;
	const char *num = NULL;
	long int tmp;

	if (!strncmp(file, "/dev/fd/", sizeof("/dev/fd/") - 1))
		num = &file[sizeof("/dev/fd/") - 1];
	else if (!strncmp(file, "/proc/self/fd/", sizeof("/proc/self/fd/") - 1))
		num = &file[sizeof("/proc/self/fd/") - 1];
	else if (!strcmp(file, "/dev/stdin"))
		num = "0";
	else if (!strcmp(file, "/dev/stdout"))
		num = "1";
	else if (!strcmp(file, "/dev/stderr"))
		num = "2";

	if (num && isdigit(*num)) {
		errno = 0;
		tmp = strtol(num, (void *)&num, 10);
		if (!errno && tmp >= 0 &&
#if INT_MAX < LONG_MAX
		    tmp < INT_MAX &&
#endif
		    !*num) {
			ret = fdopen((int)tmp, mode);
			if (!ret)
				eprintf("fdopen %li %s:", tmp, mode);
			return ret;
		}
	}

	ret = fopen(file, mode);
	if (!ret)
		eprintf("fopen %s %s:", file, mode);
	return ret;
}
