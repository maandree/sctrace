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


char *argv0;


enum Type {
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


static void
usage(void)
{
	fprintf(stderr, "usage: %s [-f trace-output-file] command ...\n", argv0);
	exit(1);
}


static char *
get_string(pid_t pid, unsigned long int addr, size_t *lenp, const char **errorp)
{
	struct iovec inv, outv;
	size_t off = 0, size = 0, page_off, read_size;
	char *out = NULL, *in = (char *)addr, *p;
	page_off = (size_t)addr % sizeof(PAGE_SIZE);
	read_size = PAGE_SIZE - page_off;
	*errorp = NULL;
	for (;; read_size = PAGE_SIZE) {
		out = realloc(out, size + PAGE_SIZE);
		if (!out) {
			fprintf(stderr, "%s: realloc: %s\n", argv0, strerror(errno));
			exit(1);
		}
		inv.iov_base  = &in[off];
		inv.iov_len   = read_size;
		outv.iov_base = &out[off];
		outv.iov_len  = read_size;
		if (process_vm_readv(pid, &outv, 1, &inv, 1, 0) != (ssize_t)read_size) {
			*errorp = errno == EFAULT ? "<invalid address>" : "<an error occured during reading of string>";
			*lenp = 0;
			return 0;
		}
		p = memchr(&out[off], 0, read_size);
		if (p) {
			*lenp = (size_t)(p - out);
			return out;
		}
		off += read_size;
	}
}


static int
get_struct(pid_t pid, unsigned long int addr, void *out, size_t size, const char **errorp)
{
	struct iovec inv, outv;
	*errorp = NULL;
	inv.iov_base  = (void *)addr;
	inv.iov_len   = size;
	outv.iov_base = out;
	outv.iov_len  = size;
	if (process_vm_readv(pid, &outv, 1, &inv, 1, 0) == (ssize_t)size)
		return 0;
	*errorp = errno == EFAULT ? "<invalid address>" : "<an error occured during reading of string>";
	return -1;
}

static char *
get_memory(pid_t pid, unsigned long int addr, size_t n, const char **errorp)
{
	char *out = malloc(n + (size_t)!n);
	if (!out) {
		fprintf(stderr, "%s: malloc: %s\n", argv0, strerror(errno));
		exit(1);
	}
	if (get_struct(pid, addr, out, n, errorp)) {
		free(out);
		return NULL;
	}
	return out;
}



static void
add_char(char **strp, size_t *sizep, size_t *lenp, char c)
{
	if (*lenp == *sizep) {
		*strp = realloc(*strp, *sizep += 128);
		if (!*strp) {
			fprintf(stderr, "%s: realloc: %s\n", argv0, strerror(errno));
			exit(1);
		}
	}
	(*strp)[(*lenp)++] = c;
}


static size_t
utf8len(char *str)
{
	size_t ext, i, len;
	uint32_t code;
	uint8_t *s = (uint8_t *)str;

	struct {
		uint8_t  lower;
		uint8_t  upper;
		uint8_t  mask;
		uint32_t lowest;
	} lookup[] = {
		{ 0x00, 0x7F, 0x7F, UINT32_C(0x000000) },
		{ 0xC0, 0xDF, 0x1F, UINT32_C(0x000080) },
		{ 0xE0, 0xEF, 0x0F, UINT32_C(0x000800) },
		{ 0xF0, 0xF7, 0x07, UINT32_C(0x010000) }
	};

	for (ext = 0; ext < sizeof(lookup) / sizeof(*lookup); ext++)
		if (lookup[ext].lower <= s[0] && s[0] <= lookup[ext].upper)
			goto found;
	return 0;

found:
	code = (uint32_t)(s[0] & lookup[ext].mask);
	len = ext + 1;
	for (i = 1; i < len; i++) {
		if ((s[i] & 0xC0) != 0x80)
			return 0;
		code = (code << 6) | (s[i] ^ 0x80);
	}

	if (code < lookup[ext].lowest || (0xD800 <= code && code <= 0xDFFF) || code > UINT32_C(0x10FFFF))
		return 0;
	return len;
}


static char *
escape_memory(char *str, size_t m)
{
	char *ret = NULL, *s, *end;
	size_t size = 0;
	size_t len = 0;
	size_t n = 0;
	int need_new_string = 0;
	if (!str) {
		str = strdup("NULL");
		if (!str) {
			fprintf(stderr, "%s: strdup: %s\n", argv0, strerror(errno));
			exit(1);
		}
		return str;
	}
	add_char(&ret, &size, &len, '"');
	for (s = str, end = &str[m]; s != end; s++) {
		if (n) {
			add_char(&ret, &size, &len, *s);
			n -= 1;
		} else if (*s == '\r') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'r');
		} else if (*s == '\t') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 't');
		} else if (*s == '\a') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'a');
		} else if (*s == '\f') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'f');
		} else if (*s == '\v') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'v');
		} else if (*s == '\b') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'b');
		} else if (*s == '\n') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, 'n');
		} else if (*s == '\"') {
			add_char(&ret, &size, &len, '\\');
			add_char(&ret, &size, &len, '"');
		} else if (*s < ' ' || *s >= 127) {
			n = utf8len(s);
			if (n > 1) {
				add_char(&ret, &size, &len, *s);
				n -= 1;
			} else {
				n = 0;
				add_char(&ret, &size, &len, '\\');
				add_char(&ret, &size, &len, 'x');
				add_char(&ret, &size, &len, "0123456789abcdef"[(int)*(unsigned char *)s >> 4]);
				add_char(&ret, &size, &len, "0123456789abcdef"[(int)*(unsigned char *)s & 15]);
				need_new_string = 1;
				continue;
			}
		} else {
			if (need_new_string && isxdigit(*s)) {
				add_char(&ret, &size, &len, '"');
				add_char(&ret, &size, &len, '"');
			}
			add_char(&ret, &size, &len, *s);
		}
		need_new_string = 0;
	}
	add_char(&ret, &size, &len, '"');
	add_char(&ret, &size, &len, '\0');
	free(str);
	return ret;
}


static void
fprint_clockid(FILE *fp, pid_t pid, unsigned long int args[6], size_t arg_index) /* TODO */
{
	(void) pid;
	fprintf(fp, "%li", (long int)args[arg_index]);
}


static void
fprint_timespec(FILE *fp, pid_t pid, unsigned long int args[6], size_t arg_index)
{
	struct timespec ts;
	const char *err;
	if (get_struct(pid, args[arg_index], &ts, sizeof(ts), &err)) {
		fprintf(fp, "%s", err);
		return;
	}
	fprintf(fp, "{.tv_sec = %ji, .tv_nsec = %li}", (intmax_t)ts.tv_sec, ts.tv_nsec);
}


static void
fprint_systemcall(FILE *fp, pid_t pid, const char *scall, const char *fmt, unsigned long int args[6], ...)
{
	typedef char *(*Function)(FILE *fp, pid_t pid, unsigned long int args[6], size_t arg_index);
	Function funcs[6];
	size_t i, nfuncs = 0, func, len;
	int ells = 0;
	char *str;
	const char *err;
	va_list ap;
	va_start(ap, args);
	fprintf(fp, "%s(", scall);
	for (i = 0; *fmt; fmt++) {
		if (*fmt == ' ')
			continue;
		if (*fmt == 'l') {
			ells += 1;
			continue;
		} else if (*fmt == 'L') {
			ells += 2;
			continue;
		} else if (*fmt == 'h') {
			ells -= 1;
			continue;
		} else if (*fmt == 'H') {
			ells -= 2;
			continue;
		}
		if (i)
			fprintf(fp, ", ");
		if (*fmt == 'p') {
			if (args[i])
				fprintf(fp, "%p", (void *)args[i]);
			else
				fprintf(fp, "NULL");
		} else if (*fmt >= '1' && *fmt <= '6') {
			func = (size_t)(*fmt - '0');
			while (nfuncs < func)
				funcs[nfuncs++] = va_arg(ap, Function);
			funcs[func - 1](fp, pid, args, i);
		} else if (*fmt == 's') {
			str = get_string(pid, args[i], &len, &err);
			str = escape_memory(str, len);
			fprintf(fp, "%s", str ? str : err);
			free(str);
		} else if (*fmt == 'm') {
			str = escape_memory(get_memory(pid, args[i], (size_t)args[i + 1], &err), (size_t)args[i + 1]);
			fprintf(fp, "%s", str ? str : err);
			free(str);
		} else if (*fmt == 'F') {
			if ((int)args[i] == AT_FDCWD)
				fprintf(fp, "AT_FDCWD");
			else
				fprintf(fp, "%i", (int)args[i]);
		} else if (*fmt == 'u') {
			if (ells == 1)
				fprintf(fp, "%lu", (unsigned long int)args[i]);
			else if (ells > 1)
				fprintf(fp, "%llu", (unsigned long long int)args[i]);
			else
				fprintf(fp, "%u", (unsigned int)args[i]);
		} else if (*fmt == 'x') {
			if (ells == 1)
				fprintf(fp, "%#lx", (unsigned long int)args[i]);
			else if (ells > 1)
				fprintf(fp, "%#llx", (unsigned long long int)args[i]);
			else
				fprintf(fp, "%#x", (unsigned int)args[i]);
		} else if (*fmt == 'o') {
			if (ells == 1)
				fprintf(fp, "%#lo", (unsigned long int)args[i]);
			else if (ells > 1)
				fprintf(fp, "%#llo", (unsigned long long int)args[i]);
			else
				fprintf(fp, "%#o", (unsigned int)args[i]);
		} else {
			if (ells == 1)
				fprintf(fp, "%li", (long int)args[i]);
			else if (ells > 1)
				fprintf(fp, "%lli", (long long int)args[i]);
			else
				fprintf(fp, "%i", (int)args[i]);
		}
		ells = 0;
		i += 1;
	}
	fprintf(fp, ")");
	va_end(ap);
}


static void
print_systemcall(FILE *fp, pid_t pid, unsigned long long int scall, unsigned long int args[6], enum Type *ret_type)
{
	char buf1[128], *p, *buf;
	unsigned long int flags;

#define FLAGS_BEGIN(BUF, ARG)\
	p = buf = (BUF);\
	flags = (ARG)
#define FLAGS_ADD(FLAG)\
	if (flags & (unsigned long int)(FLAG))\
		p = stpcpy(p, "|"#FLAG)
#define FLAGS_END(FMT, TYPE)\
	if (flags || p == buf)\
		sprintf(p, "|"FMT, (TYPE)flags);

#define UNDOCUMENTED(NAME) GENERIC_HANDLER(NAME)
#define UNIMPLEMENTED(NAME) GENERIC_HANDLER(NAME)
#define GENERIC_HANDLER(NAME)\
	case SYS_##NAME:\
		fprintf(fp, "%s(raw: %lu, %lu, %lu, %lu, %lu, %lu)", #NAME,\
		        args[0], args[1], args[2], args[3], args[4], args[5]);\
		break
#define SIMPLE(NAME, FMT, RET_TYPE)\
	case SYS_##NAME:\
		fprint_systemcall(fp, pid, #NAME, (FMT), args);\
		*ret_type = (RET_TYPE);\
		break	
#define FORMATTERS(NAME, FMT, RET_TYPE, ...)\
	case SYS_##NAME:\
		fprint_systemcall(fp, pid, #NAME, (FMT), args, __VA_ARGS__);\
		*ret_type = (RET_TYPE);\
		break	

	*ret_type = Unknown;

	/* TODO replace GENERIC_HANDLER with specific handlers */
	switch (scall) {
	GENERIC_HANDLER(_sysctl);
	SIMPLE(accept, "ipp", Int); /* TODO output */
	case SYS_accept4: /* TODO output */
		FLAGS_BEGIN(buf1, args[3]);
		FLAGS_ADD(SOCK_NONBLOCK);
		FLAGS_ADD(SOCK_CLOEXEC);
		FLAGS_END("%#x", unsigned int);
		fprintf(fp, "accept4(%i, %p, %p, %s)", (int)args[0], (void *)args[1], (void *)args[2], &buf1[1]);
		*ret_type = Int;
		break;
	SIMPLE(access, "si", Int); /* TODO flags */
	SIMPLE(acct, "s", Int);
	GENERIC_HANDLER(add_key);
	GENERIC_HANDLER(adjtimex);
	UNIMPLEMENTED(afs_syscall);
	SIMPLE(alarm, "", UInt);
	GENERIC_HANDLER(arch_prctl);
	GENERIC_HANDLER(bind);
	GENERIC_HANDLER(bpf);
	SIMPLE(brk, "p", Int);
	GENERIC_HANDLER(capget);
	GENERIC_HANDLER(capset);
	SIMPLE(chdir, "s", Int);
	SIMPLE(chmod, "so", Int);
	SIMPLE(chown, "sii", Int);
	SIMPLE(chroot, "s", Int);
	UNDOCUMENTED(clock_adjtime);
	FORMATTERS(clock_getres, "1p", Int, fprint_clockid); /* TODO output */
	FORMATTERS(clock_gettime, "1p", Int, fprint_clockid); /* TODO output */
	FORMATTERS(clock_nanosleep, "1i2p", Int, fprint_clockid, fprint_timespec); /* TODO output, flags */
	FORMATTERS(clock_settime, "12", Int, fprint_clockid, fprint_timespec);
	GENERIC_HANDLER(clone);
	GENERIC_HANDLER(clone3);
	SIMPLE(close, "i", Int);
	GENERIC_HANDLER(connect);
	GENERIC_HANDLER(copy_file_range);
	SIMPLE(creat, "so", Int); /* TODO flags */
	SIMPLE(create_module, "slu", Ptr);
	SIMPLE(delete_module, "si", Int); /* TODO flags */
	SIMPLE(dup, "i", Int);
	SIMPLE(dup2, "ii", Int);
	SIMPLE(dup3, "iii", Int);
	SIMPLE(epoll_create, "i", Int);
	case SYS_epoll_create1:\
		FLAGS_BEGIN(buf1, args[0]);
		FLAGS_ADD(EPOLL_CLOEXEC);
		FLAGS_END("%#x", unsigned int);
		fprintf(fp, "epoll_create1(%s)", &buf1[1]);
		*ret_type = Int;
		break;
	GENERIC_HANDLER(epoll_ctl);
	GENERIC_HANDLER(epoll_ctl_old);
	GENERIC_HANDLER(epoll_pwait);
	GENERIC_HANDLER(epoll_wait);
	GENERIC_HANDLER(epoll_wait_old);
	GENERIC_HANDLER(eventfd);
	GENERIC_HANDLER(eventfd2);
	GENERIC_HANDLER(execve);
	GENERIC_HANDLER(execveat);
	SIMPLE(exit, "i", Int);
	SIMPLE(exit_group, "i", Int);
	SIMPLE(faccessat, "Fsii", Int); /* TODO flags */
	GENERIC_HANDLER(fadvise64);
	GENERIC_HANDLER(fallocate);
	GENERIC_HANDLER(fanotify_init);
	GENERIC_HANDLER(fanotify_mark);
	SIMPLE(fchdir, "i", Int);
	SIMPLE(fchmod, "io", Int);
	SIMPLE(fchmodat, "Fsoi", Int); /* TODO flags */
	SIMPLE(fchown, "iii", Int);
	SIMPLE(fchownat, "Fsiii", Int); /* TODO flags */
	GENERIC_HANDLER(fcntl);
	SIMPLE(fdatasync, "i", Int);
	SIMPLE(fgetxattr, "isplu", Long); /* TODO output */
	GENERIC_HANDLER(finit_module);
	GENERIC_HANDLER(flistxattr);
	GENERIC_HANDLER(flock);
	SIMPLE(fork, "", Int); /* TODO fork */
	SIMPLE(fremovexattr, "is", Int);
	UNDOCUMENTED(fsconfig);
	SIMPLE(fsetxattr, "ismlui", Int); /* TODO flags */
	UNDOCUMENTED(fsmount);
	UNDOCUMENTED(fsopen);
	UNDOCUMENTED(fspick);
	SIMPLE(fstat, "ip", Int); /* TODO output */
	SIMPLE(fstatfs, "ip", Int); /* TODO output */
	SIMPLE(fsync, "i", Int);
	SIMPLE(ftruncate, "illi", Int);
	GENERIC_HANDLER(futex);
	GENERIC_HANDLER(futimesat);
	GENERIC_HANDLER(get_kernel_syms);
	GENERIC_HANDLER(get_mempolicy);
	GENERIC_HANDLER(get_robust_list);
	GENERIC_HANDLER(get_thread_area);
	GENERIC_HANDLER(getcpu);
	GENERIC_HANDLER(getcwd);
	GENERIC_HANDLER(getdents);
	GENERIC_HANDLER(getdents64);
	SIMPLE(getegid, "", Int);
	SIMPLE(geteuid, "", Int);
	SIMPLE(getgid, "", Int);
	GENERIC_HANDLER(getgroups);
	GENERIC_HANDLER(getitimer);
	GENERIC_HANDLER(getpeername);
	SIMPLE(getpgid, "i", Int);
	GENERIC_HANDLER(getpgrp);
	SIMPLE(getpid, "", Int);
	UNIMPLEMENTED(getpmsg);
	SIMPLE(getppid, "", Int);
	SIMPLE(getpriority, "ii", Int);
	SIMPLE(getrandom, "pluu", Long); /* TODO output, flags */
	SIMPLE(getresgid, "ppp", Int); /* TODO output */
	SIMPLE(getresuid, "ppp", Int); /* TODO output */
	GENERIC_HANDLER(getrlimit);
	GENERIC_HANDLER(getrusage);
	SIMPLE(getsid, "i", Int);
	GENERIC_HANDLER(getsockname);
	GENERIC_HANDLER(getsockopt);
	SIMPLE(gettid, "", Int);
	GENERIC_HANDLER(gettimeofday);
	SIMPLE(getuid, "", Int);
	SIMPLE(getxattr, "ssplu", Long); /* TODO output */
	GENERIC_HANDLER(init_module);
	SIMPLE(inotify_add_watch, "isx", Int); /* TODO flags */
	SIMPLE(inotify_init, "", Int);
	SIMPLE(inotify_init1, "i", Int); /* TODO flags */
	SIMPLE(inotify_rm_watch, "ii", Int);
	GENERIC_HANDLER(io_cancel);
	GENERIC_HANDLER(io_destroy);
	GENERIC_HANDLER(io_getevents);
	GENERIC_HANDLER(io_pgetevents);
	GENERIC_HANDLER(io_setup);
	GENERIC_HANDLER(io_submit);
	UNDOCUMENTED(io_uring_enter);
	UNDOCUMENTED(io_uring_register);
	UNDOCUMENTED(io_uring_setup);
	GENERIC_HANDLER(ioctl);
	SIMPLE(ioperm, "lului", Int);
	SIMPLE(iopl, "i", Int);
	GENERIC_HANDLER(ioprio_get);
	GENERIC_HANDLER(ioprio_set);
	GENERIC_HANDLER(kcmp);
	GENERIC_HANDLER(kexec_file_load);
	GENERIC_HANDLER(kexec_load);
	GENERIC_HANDLER(keyctl);
	SIMPLE(kill, "ii", Int); /* TODO flags */
	SIMPLE(lchown, "sii", Int);
	SIMPLE(lgetxattr, "ssplu", Long); /* TODO output */
	SIMPLE(link, "ss", Int);
	SIMPLE(linkat, "FsFsi", Int); /* TODO flags */
	SIMPLE(listen, "ii", Int);
	GENERIC_HANDLER(listxattr);
	GENERIC_HANDLER(llistxattr);
	GENERIC_HANDLER(lookup_dcookie);
	SIMPLE(lremovexattr, "ss", Int);
	SIMPLE(lseek, "illii", LLong); /* TODO flags */
	SIMPLE(lsetxattr, "ssmlui", Int); /* TODO flags */
	SIMPLE(lstat, "sp", Int); /* TODO output */
	SIMPLE(madvise, "plui", Int); /* TODO flags */
	GENERIC_HANDLER(mbind);
	SIMPLE(membarrier, "ii", Int); /* TODO flags */
	SIMPLE(memfd_create, "su", Int); /* TODO flags */
	GENERIC_HANDLER(migrate_pages);
	GENERIC_HANDLER(mincore);
	SIMPLE(mkdir, "so", Int);
	SIMPLE(mkdirat, "Fso", Int);
	GENERIC_HANDLER(mknod);
	GENERIC_HANDLER(mknodat);
	SIMPLE(mlock, "plu", Int);
	SIMPLE(mlock2, "plui", Int); /* TODO flags */
	SIMPLE(mlockall, "i", Int); /* TODO flags */
	SIMPLE(mmap, "pluiiilli", Ptr); /* TODO flags */
	GENERIC_HANDLER(modify_ldt);
	GENERIC_HANDLER(mount);
	UNDOCUMENTED(move_mount);
	GENERIC_HANDLER(move_pages);
	SIMPLE(mprotect, "plui", Int); /* TODO flags */
	GENERIC_HANDLER(mq_getsetattr);
	GENERIC_HANDLER(mq_notify);
	GENERIC_HANDLER(mq_open);
	GENERIC_HANDLER(mq_timedreceive);
	GENERIC_HANDLER(mq_timedsend);
	GENERIC_HANDLER(mq_unlink);
	GENERIC_HANDLER(mremap);
	GENERIC_HANDLER(msgctl);
	GENERIC_HANDLER(msgget);
	GENERIC_HANDLER(msgrcv);
	GENERIC_HANDLER(msgsnd);
	SIMPLE(msync, "plui", Int); /* TODO flags */
	SIMPLE(munlock, "plu", Int);
	SIMPLE(munlockall, "", Int);
	SIMPLE(munmap, "plu", Int);
	GENERIC_HANDLER(name_to_handle_at);
	FORMATTERS(nanosleep, "1p", Int, fprint_timespec); /* TODO output */
	SIMPLE(newfstatat, "Fspi", Int); /* TODO output, flags */
	SIMPLE(nfsservctl, "ipp", Long); /* TODO flags, struct, output */
	GENERIC_HANDLER(open);
	GENERIC_HANDLER(open_by_handle_at);
	UNDOCUMENTED(open_tree);
	GENERIC_HANDLER(openat);
	SIMPLE(pause, "", Int);
	GENERIC_HANDLER(perf_event_open);
	GENERIC_HANDLER(personality);
	SIMPLE(pidfd_open, "iu", Int);
	GENERIC_HANDLER(pidfd_send_signal);
	SIMPLE(pipe, "p", Int); /* TODO output */
	SIMPLE(pipe2, "pi", Int); /* TODO output, flags */
	SIMPLE(pivot_root, "ss", Int);
	SIMPLE(pkey_alloc, "lulu", Int); /* TODO flags */
	SIMPLE(pkey_free, "i", Int);
	SIMPLE(pkey_mprotect, "pluii", Int); /* TODO flags */
	GENERIC_HANDLER(poll);
	GENERIC_HANDLER(ppoll);
	GENERIC_HANDLER(prctl);
	GENERIC_HANDLER(pread64);
	GENERIC_HANDLER(preadv);
	GENERIC_HANDLER(preadv2);
	GENERIC_HANDLER(prlimit64);
	GENERIC_HANDLER(process_vm_readv);
	GENERIC_HANDLER(process_vm_writev);
	GENERIC_HANDLER(pselect6);
	GENERIC_HANDLER(ptrace);
	UNIMPLEMENTED(putpmsg);
	GENERIC_HANDLER(pwrite64);
	GENERIC_HANDLER(pwritev);
	GENERIC_HANDLER(pwritev2);
	GENERIC_HANDLER(query_module);
	GENERIC_HANDLER(quotactl);
	SIMPLE(read, "iplu", Long); /* TODO output */
	SIMPLE(readahead, "illilu", Long);
	SIMPLE(readlink, "splu", Long); /* TODO output */
	SIMPLE(readlinkat, "Fsplu", Long); /* TODO output */
	GENERIC_HANDLER(readv);
	GENERIC_HANDLER(reboot);
	GENERIC_HANDLER(recvfrom);
	GENERIC_HANDLER(recvmmsg);
	GENERIC_HANDLER(recvmsg);
	GENERIC_HANDLER(remap_file_pages);
	SIMPLE(removexattr, "ss", Int);
	SIMPLE(rename, "ss", Int);
	SIMPLE(renameat, "FsFs", Int);
	SIMPLE(renameat2, "FsFsu", Int); /* TODO flags */
	GENERIC_HANDLER(request_key);
	SIMPLE(restart_syscall, "", Int);
	SIMPLE(rmdir, "s", Int);
	UNDOCUMENTED(rseq);
	GENERIC_HANDLER(rt_sigaction);
	GENERIC_HANDLER(rt_sigpending);
	GENERIC_HANDLER(rt_sigprocmask);
	GENERIC_HANDLER(rt_sigqueueinfo);
	GENERIC_HANDLER(rt_sigreturn);
	GENERIC_HANDLER(rt_sigsuspend);
	GENERIC_HANDLER(rt_sigtimedwait);
	GENERIC_HANDLER(rt_tgsigqueueinfo);
	SIMPLE(sched_get_priority_max, "i", Int);
	SIMPLE(sched_get_priority_min, "i", Int);
	GENERIC_HANDLER(sched_getaffinity);
	GENERIC_HANDLER(sched_getattr);
	GENERIC_HANDLER(sched_getparam);
	GENERIC_HANDLER(sched_getscheduler);
	GENERIC_HANDLER(sched_rr_get_interval);
	GENERIC_HANDLER(sched_setaffinity);
	GENERIC_HANDLER(sched_setattr);
	GENERIC_HANDLER(sched_setparam);
	GENERIC_HANDLER(sched_setscheduler);
	SIMPLE(sched_yield, "", Int);
	GENERIC_HANDLER(seccomp);
	UNIMPLEMENTED(security);
	GENERIC_HANDLER(select);
	GENERIC_HANDLER(semctl);
	GENERIC_HANDLER(semget);
	GENERIC_HANDLER(semop);
	GENERIC_HANDLER(semtimedop);
	GENERIC_HANDLER(sendfile);
	GENERIC_HANDLER(sendmmsg);
	GENERIC_HANDLER(sendmsg);
	GENERIC_HANDLER(sendto);
	GENERIC_HANDLER(set_mempolicy);
	GENERIC_HANDLER(set_robust_list);
	GENERIC_HANDLER(set_thread_area);
	SIMPLE(set_tid_address, "p", Long);
	GENERIC_HANDLER(setdomainname);
	SIMPLE(setfsgid, "i", Int);
	SIMPLE(setfsuid, "i", Int);
	SIMPLE(setgid, "i", Int);
	GENERIC_HANDLER(setgroups);
	GENERIC_HANDLER(sethostname);
	GENERIC_HANDLER(setitimer);
	GENERIC_HANDLER(setns);
	SIMPLE(setpgid, "ii", Int);
	SIMPLE(setpriority, "iii", Int);
	SIMPLE(setregid, "ii", Int);
	SIMPLE(setresgid, "iii", Int);
	SIMPLE(setresuid, "iii", Int);
	SIMPLE(setreuid, "ii", Int);
	GENERIC_HANDLER(setrlimit);
	SIMPLE(setsid, "", Int);
	GENERIC_HANDLER(setsockopt);
	GENERIC_HANDLER(settimeofday);
	SIMPLE(setuid, "i", Int);
	SIMPLE(setxattr, "ssmlui", Int); /* TODO flags */
	GENERIC_HANDLER(shmat);
	GENERIC_HANDLER(shmctl);
	GENERIC_HANDLER(shmdt);
	GENERIC_HANDLER(shmget);
	SIMPLE(shutdown, "ii", Int); /* TODO flags */
	GENERIC_HANDLER(sigaltstack);
	GENERIC_HANDLER(signalfd);
	GENERIC_HANDLER(signalfd4);
	SIMPLE(socket, "iii", Int); /* TODO flags */
	SIMPLE(socketpair, "iiip", Int); /* TODO output, flags */
	GENERIC_HANDLER(splice);
	GENERIC_HANDLER(stat);
	GENERIC_HANDLER(statfs);
	GENERIC_HANDLER(statx);
	SIMPLE(swapoff, "s", Int);
	SIMPLE(swapon, "si", Int); /* TODO flags */
	SIMPLE(symlink, "ss", Int);
	SIMPLE(symlinkat, "sFs", Int);
	SIMPLE(sync, "", Void);
	SIMPLE(sync_file_range, "illilliu", Int); /* TODO flags */
	SIMPLE(syncfs, "i", Int);
	GENERIC_HANDLER(sysfs);
	GENERIC_HANDLER(sysinfo);
	GENERIC_HANDLER(syslog);
	GENERIC_HANDLER(tee);
	SIMPLE(tgkill, "iii", Int); /* TODO flags */
	SIMPLE(time, "p", LLong); /* TODO output */
	GENERIC_HANDLER(timer_create);
	GENERIC_HANDLER(timer_delete);
	GENERIC_HANDLER(timer_getoverrun);
	GENERIC_HANDLER(timer_gettime);
	GENERIC_HANDLER(timer_settime);
	GENERIC_HANDLER(timerfd_create);
	GENERIC_HANDLER(timerfd_gettime);
	GENERIC_HANDLER(timerfd_settime);
	GENERIC_HANDLER(times);
	SIMPLE(tkill, "ii", Int); /* TODO flags */
	SIMPLE(truncate, "slli", Int);
	UNIMPLEMENTED(tuxcall);
	SIMPLE(umask, "o", OInt);
	SIMPLE(umount2, "si", Int); /* TODO flags */
	SIMPLE(uname, "p", Int); /* TODO output */
	SIMPLE(unlink, "s", Int);
	SIMPLE(unlinkat, "Fsi", Int); /* TODO flags */
	SIMPLE(unshare, "i", Int); /* TODO flags */
	SIMPLE(uselib, "s", Int);
	SIMPLE(userfaultfd, "i", Int); /* TODO flags */
	GENERIC_HANDLER(ustat);
	GENERIC_HANDLER(utime);
	GENERIC_HANDLER(utimensat);
	GENERIC_HANDLER(utimes);
	SIMPLE(vfork, "", Int); /* TODO fork */
	SIMPLE(vhangup, "", Int);
	GENERIC_HANDLER(vmsplice);
	UNIMPLEMENTED(vserver);
	GENERIC_HANDLER(wait4);
	GENERIC_HANDLER(waitid);
	SIMPLE(write, "imlu", Long);
	GENERIC_HANDLER(writev);
	default:
		fprintf(fp, "syscall_0x%lx(raw: %lu, %lu, %lu, %lu, %lu, %lu)", (unsigned long int)scall,
		        args[0], args[1], args[2], args[3], args[4], args[5]);
		break;
	}
}


int
main(int argc, char **argv)
{
	pid_t pid;
	struct user_regs_struct regs;
	unsigned long long int scall;
	long int tmp;
	unsigned long int args[6];
	enum Type ret_type;
	char *outfile = NULL;
	FILE *outfp = stderr;
	const char *num = NULL;

	/* TODO add option to trace children */
	/* TODO add option to trace threads */
	/* TODO add option to specify argv[0] */
	ARGBEGIN {
	case 'f':
		if (outfile)
			usage();
		outfile = EARGF(usage());
		break;
	default:
		usage();
	} ARGEND;
	if (!argc)
		usage();

	/* Start program to trace */
	pid = fork();
	switch (pid) {
	case -1:
		fprintf(stderr, "%s: fork: %s\n", argv0, strerror(errno));
		return 1;
	case 0:
		if (ptrace(PTRACE_TRACEME, 0, NULL, 0)) {
			fprintf(stderr, "%s: ptrace PTRACE_TRACEME 0 NULL 0: %s\n", argv0, strerror(errno));
			return 1;
		}
		/* exec will block until parent attaches */
		execvp(*argv, argv);
		fprintf(stderr, "%s: execvp %s: %s\n", argv0, *argv, strerror(errno));
		exit(1);
	default:
		if (waitpid(pid, NULL, 0) < 0) { /* Wait for exec */
			fprintf(stderr, "%s: waitpid <tracee> NULL 0: %s\n", argv0, strerror(errno));
			kill(pid, SIGKILL);
			return 1;
		}
		if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL)) {
			fprintf(stderr, "%s: waitpid <tracee> NULL 0: %s\n", argv0, strerror(errno));
			kill(pid, SIGKILL);
			return 1;
		}
		/* TODO check that tracee is x86-64 */
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
					fprintf(stderr, "%s: fdopen %li wb: %s\n", argv0, tmp, strerror(errno));
					return 1;
				}
				goto have_outfp;
			}
		}
		outfp = fopen(outfile, "wb");
		if (!outfp) {
			fprintf(stderr, "%s: fopen %s wb: %s\n", argv0, outfile, strerror(errno));
			return 1;
		}
	}
have_outfp:

	for (;;) {
		/* Wait for next syscall */
		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0)) {
			fprintf(stderr, "%s: ptrace PTRACE_SYSCALL <tracee> NULL 0: %s\n", argv0, strerror(errno));
			return 1;
		}
		if (waitpid(pid, 0, 0) < 0) {
			fprintf(stderr, "%s: waitpid <tracee> NULL 0: %s\n", argv0, strerror(errno));
			return 1;
		}

		/* Get systemcall arguments */
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
			fprintf(stderr, "%s: ptrace PTRACE_GETREGS <tracee> NULL <buffer>: %s\n", argv0, strerror(errno));
			return 1;
		}
		scall = regs.orig_rax;
		args[0] = regs.rdi;
		args[1] = regs.rsi;
		args[2] = regs.rdx;
		args[3] = regs.r10;
		args[4] = regs.r8;
		args[5] = regs.r9;

		/* Print system call */
		print_systemcall(outfp, pid, scall, args, &ret_type);

		/* Run system call */
		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0)) {
			fprintf(stderr, "%s: ptrace PTRACE_SYSCALL <tracee> NULL 0: %s\n", argv0, strerror(errno));
			return 1;
		}
		if (waitpid(pid, 0, 0) == -1) {
			fprintf(stderr, "%s: waitpid <tracee> NULL 0: %s\n", argv0, strerror(errno));
			return 1;
		}

		/* Get system call result */
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
			fprintf(outfp, " = ?\n");
			if (errno == ESRCH)
				exit((int)regs.rdi);
			fprintf(stderr, "%s: ptrace PTRACE_GETREGS <tracee> NULL <buffer>: %s\n", argv0, strerror(errno));
		}

		/* Print system call result */
		/* TODO print error name (not one all system calls) */
		if (ret_type == Int)
			fprintf(outfp, " = %i\n", (int)regs.rax);
		else if (ret_type == UInt)
			fprintf(outfp, " = %u\n", (unsigned int)regs.rax);
		else if (ret_type == OInt)
			fprintf(outfp, " = %#o\n", (unsigned int)regs.rax);
		else if (ret_type == XInt)
			fprintf(outfp, " = %#x\n", (unsigned int)regs.rax);
		else if (ret_type == Long)
			fprintf(outfp, " = %li\n", (long int)regs.rax);
		else if (ret_type == ULong)
			fprintf(outfp, " = %lu\n", (unsigned long int)regs.rax);
		else if (ret_type == OLong)
			fprintf(outfp, " = %#lo\n", (unsigned long int)regs.rax);
		else if (ret_type == XLong)
			fprintf(outfp, " = %#lx\n", (unsigned long int)regs.rax);
		else if (ret_type == LLong)
			fprintf(outfp, " = %lli\n", (long long int)regs.rax);
		else if (ret_type == ULLong)
			fprintf(outfp, " = %llu\n", (unsigned long long int)regs.rax);
		else if (ret_type == OLLong)
			fprintf(outfp, " = %#llo\n", (unsigned long long int)regs.rax);
		else if (ret_type == XLLong)
			fprintf(outfp, " = %#llx\n", (unsigned long long int)regs.rax);
		else if (ret_type == Ptr && (long long int)regs.rax >= 0)
			fprintf(outfp, " = %p\n", (void *)regs.rax);
		else
			fprintf(outfp, " = %li\n", (long int)regs.rax);
	}

	fclose(outfp);
	return 0;
}
