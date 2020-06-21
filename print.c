/* See LICENSE file for copyright and license details. */
#include "common.h"

#include <linux/memfd.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <linux/fs.h> /* after <sys/mount.h> */
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <sched.h>
#include <time.h>

#if defined(__linux__)
# ifndef CLONE_NEWTIME
#  define CLONE_NEWTIME 0x00000080
# endif
#endif


#define CASE(N)\
	do {\
		if (proc->args[arg_index] == N) {\
			tprintf(proc, "%s", #N);\
			return;\
		}\
	} while (0)

#define FLAGS_BEGIN\
	do {\
		char buf[1024] = {0};\
		char *p = buf;\
		unsigned long long int flags = proc->args[arg_index]

#define FLAG(FLAG)\
		do {\
			_Static_assert((FLAG) != 0, #FLAG" is 0 and must not be included");\
			if (flags & (FLAG)) {\
				p = stpcpy(p, "|"#FLAG);\
				flags ^= (FLAG);\
			}\
		} while (0)

#define FLAGS_END\
		if (flags || !*buf)\
			sprintf(p, "|%#llx", flags);\
		tprintf(proc, "%s", &buf[1]);\
	} while (0)

#define FLAGS_END_DEFAULT(FLAG)\
		_Static_assert((FLAG) == 0, #FLAG" is not 0 and cannot be the default");\
		if (!flags && !*buf)\
			sprintf(p, "|%s", #FLAG);\
		else if (flags || !*buf)\
			sprintf(p, "|%#llx", flags);\
		tprintf(proc, "%s", &buf[1]);\
	} while (0)



static void
print_accept4_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(SOCK_NONBLOCK);
	FLAG(SOCK_CLOEXEC);
	FLAGS_END;
}

static void
print_access_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(R_OK);
	FLAG(W_OK);
	FLAG(X_OK);
	FLAGS_END_DEFAULT(F_OK);
}

static void
print_faccessat_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(AT_EACCESS);
	FLAG(AT_SYMLINK_NOFOLLOW);
	FLAGS_END;
}

static void
print_clockid(struct process *proc, size_t arg_index)
{
	CASE(CLOCK_REALTIME);
	CASE(CLOCK_MONOTONIC);
	CASE(CLOCK_PROCESS_CPUTIME_ID);
	CASE(CLOCK_THREAD_CPUTIME_ID);
	CASE(CLOCK_MONOTONIC_RAW);
	CASE(CLOCK_REALTIME_COARSE);
	CASE(CLOCK_MONOTONIC_COARSE);
	CASE(CLOCK_BOOTTIME);
	CASE(CLOCK_REALTIME_ALARM);
	CASE(CLOCK_BOOTTIME_ALARM);
	CASE(CLOCK_TAI);
	tprintf(proc, "%li", (long int)proc->args[arg_index]);
}

static void
print_clock_nanosleep_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(TIMER_ABSTIME);
	FLAGS_END;
}

static void
print_timespec(struct process *proc, size_t arg_index)
{
	struct timespec ts;
	const char *err;
	if (get_struct(proc->pid, proc->args[arg_index], &ts, sizeof(ts), &err)) {
		tprintf(proc, "%s", err);
		return;
	}
	tprintf(proc, "{.tv_sec = %ji, .tv_nsec = %li}", (intmax_t)ts.tv_sec, ts.tv_nsec);
}

static void
print_delete_module_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(O_NONBLOCK);
	FLAG(O_TRUNC);
	FLAGS_END;
}

static void
print_dup3_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(O_CLOEXEC);
	FLAGS_END;
}

static void
print_epoll_create1_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(EPOLL_CLOEXEC);
	FLAGS_END;
}

static void
print_at_symlink_nofollow(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(AT_SYMLINK_NOFOLLOW);
	FLAGS_END;
}

static void
print_at_empty_path_at_symlink_nofollow(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(AT_EMPTY_PATH);
	FLAG(AT_SYMLINK_NOFOLLOW);
	FLAGS_END;
}

static void
print_setxattr_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(XATTR_CREATE);
	FLAG(XATTR_REPLACE);
	FLAGS_END;
}

static void
print_getrandom_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(GRND_RANDOM);
	FLAG(GRND_NONBLOCK);
	FLAGS_END;
}

static void
print_inotify_init1_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(IN_NONBLOCK);
	FLAG(IN_CLOEXEC);
	FLAGS_END;
}

static void
print_inotify_add_watch_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(IN_ACCESS);
	FLAG(IN_MODIFY);
	FLAG(IN_ATTRIB);
	FLAG(IN_CLOSE_WRITE);
	FLAG(IN_CLOSE_NOWRITE);
	FLAG(IN_OPEN);
	FLAG(IN_MOVED_FROM);
	FLAG(IN_MOVED_TO);
	FLAG(IN_CREATE);
	FLAG(IN_DELETE);
	FLAG(IN_DELETE_SELF);
	FLAG(IN_MOVE_SELF);
	FLAG(IN_ONLYDIR);
	FLAG(IN_DONT_FOLLOW);
	FLAG(IN_EXCL_UNLINK);
	FLAG(IN_MASK_CREATE);
	FLAG(IN_MASK_ADD);
	FLAG(IN_ISDIR);
	FLAG(IN_ONESHOT);
	FLAGS_END;
}

static void
print_signal_name(struct process *proc, size_t arg_index)
{
	tprintf(proc, "%s", get_signum_name((int)proc->args[arg_index]));
}

static void
print_lseek_flag(struct process *proc, size_t arg_index)
{
	CASE(SEEK_SET);
	CASE(SEEK_CUR);
	CASE(SEEK_END);
	CASE(SEEK_DATA);
	CASE(SEEK_HOLE);
	tprintf(proc, "%i", (int)proc->args[arg_index]);
}

static void
print_int_pair(struct process *proc, size_t arg_index)
{
	int pair[2];
	const char *err;
	if (get_struct(proc->pid, proc->args[arg_index], pair, sizeof(pair), &err)) {
		tprintf(proc, "%s", err);
		return;
	}
	tprintf(proc, "{%i, %i}", pair[0], pair[1]);
}

static void
print_splice_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(SPLICE_F_MOVE);
	FLAG(SPLICE_F_NONBLOCK);
	FLAG(SPLICE_F_MORE);
	FLAG(SPLICE_F_GIFT);
	FLAGS_END;
}

static void
print_mlock2_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(MLOCK_ONFAULT);
	FLAGS_END;
}

static void
print_mlockall_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(MCL_CURRENT);
	FLAG(MCL_FUTURE);
	FLAG(MCL_ONFAULT);
	FLAGS_END;
}

static void
print_shutdown_flag(struct process *proc, size_t arg_index)
{
	CASE(SHUT_RD);
	CASE(SHUT_WR);
	CASE(SHUT_RDWR);
	tprintf(proc, "%i", (int)proc->args[arg_index]);
}

static void
print_unlinkat_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(AT_REMOVEDIR);
	FLAGS_END;
}

static void
print_renameat2_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(RENAME_EXCHANGE);
	FLAG(RENAME_NOREPLACE);
	FLAG(RENAME_WHITEOUT);
	FLAGS_END;
}

static void
print_userfaultfd_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(O_CLOEXEC);
	FLAG(O_NONBLOCK);
	FLAGS_END;
}

static void
print_unshare_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(CLONE_FILES);
	FLAG(CLONE_FS);
	FLAG(CLONE_NEWCGROUP);
	FLAG(CLONE_NEWIPC);
	FLAG(CLONE_NEWNET);
	FLAG(CLONE_NEWNS);
	FLAG(CLONE_NEWPID);
	FLAG(CLONE_NEWTIME);
	FLAG(CLONE_NEWUSER);
	FLAG(CLONE_NEWUTS);
	FLAG(CLONE_SYSVSEM);
	FLAGS_END;
}

static void
print_pipe2_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(O_CLOEXEC);
	FLAG(O_DIRECT);
	FLAG(O_NONBLOCK);
	FLAGS_END;
}

static void
print_sync_file_range_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(SYNC_FILE_RANGE_WAIT_BEFORE);
	FLAG(SYNC_FILE_RANGE_WRITE);
	FLAG(SYNC_FILE_RANGE_WAIT_AFTER);
	FLAGS_END;
}

static void
print_umount2_flags(struct process *proc, size_t arg_index)
{
	FLAGS_BEGIN;
	FLAG(MNT_FORCE);
	FLAG(MNT_DETACH);
	FLAG(MNT_EXPIRE);
	FLAG(UMOUNT_NOFOLLOW);
	FLAGS_END;
}

static void
print_memfd_create_flags(struct process *proc, size_t arg_index)
{
	unsigned long long int huge;
	FLAGS_BEGIN;
	FLAG(MFD_CLOEXEC);
	FLAG(MFD_ALLOW_SEALING);
	FLAG(MFD_HUGETLB);
	huge = flags;
	huge &= (unsigned long long int)(MFD_HUGE_MASK & 0x3F) << MFD_HUGE_SHIFT;
	if (huge) {
		flags ^= huge;
		huge >>= MFD_HUGE_SHIFT;
		sprintf(p, "|MFD_HUGE_%i%c%s", 1 << ((int)huge % 10), "BKMGTPE"[huge / 10], huge >= 10 ? "B" : "");
	}
	FLAGS_END;
}


static void
printf_systemcall(struct process *proc, const char *scall, const char *fmt, ...)
{
	typedef void (*Function)(struct process *proc, size_t arg_index);
	Function funcs[6];
	size_t i, nfuncs = 0, func, len, size;
	unsigned long long int *args = proc->args, arg, value;
	int ells = 0, output = 0, input = 0;
	char *str;
	const char *err;
	va_list ap;

	va_start(ap, fmt);
	tprintf(proc, "%s(", scall);

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

		arg = args[i];

		if (output) {
			output = 0;
			proc->outputs[i - !input].fmt = *fmt;
			proc->outputs[i - !input].ells = ells;
			if ('1' <= *fmt && *fmt <= '6') {
				func = (size_t)(*fmt - '0');
				while (nfuncs < func)
					funcs[nfuncs++] = va_arg(ap, Function);
				proc->outputs[i - !input].func = funcs[nfuncs - 1];
			}
			if (!input)
				continue;
		} else if (*fmt == '>') {
			output = 1;
			if (i)
				tprintf(proc, ", ");
			goto p_fmt;
		} else if (*fmt == '&') {
			output = 1;
			input = 1;
			continue;
		}

		if (i)
			tprintf(proc, ", ");

		if (*fmt == 'p') {
		p_fmt:
			if (proc->ptr_is_int)
				arg = (unsigned int)arg;
			if (input) {
				if (proc->ptr_is_int) {
					if (get_struct(proc->pid, arg, &arg, sizeof(int), &err)) {
						tprintf(proc, "%s", err);
						goto next;
					}
					arg = *(unsigned int *)&arg;
				} else {
					if (get_struct(proc->pid, arg, &arg, sizeof(long int), &err)) {
						tprintf(proc, "%s", err);
						goto next;
					}
					arg = *(unsigned long int *)&arg;
				}
				tprintf(proc, "&");
			}
			if (arg)
				tprintf(proc, "%#llx", arg);
			else
				tprintf(proc, "NULL");
		} else if (*fmt >= '1' && *fmt <= '6') {
			func = (size_t)(*fmt - '0');
			while (nfuncs < func)
				funcs[nfuncs++] = va_arg(ap, Function);
			funcs[func - 1](proc, i);
		} else if (*fmt == 's') {
			str = get_escaped_string(proc->pid, arg, &len, &err);
			tprintf(proc, "%s", str ? str : err);
			free(str);
		} else if (*fmt == 'm') {
			str = get_escaped_memory(proc->pid, arg, (size_t)args[i + 1], &err);
			tprintf(proc, "%s", str ? str : err);
			free(str);
		} else if (*fmt == 'F') {
			if (input) {
				if (get_struct(proc->pid, arg, &arg, sizeof(int), &err)) {
					tprintf(proc, "%s", err);
					goto next;
				}
				tprintf(proc, "&");
			}
			if ((int)arg == AT_FDCWD)
				tprintf(proc, "AT_FDCWD");
			else
				tprintf(proc, "%i", (int)arg);
		} else {
			if (ells == 1 && proc->long_is_int)
				ells = 0;
			if (ells == 1)
				size = sizeof(long int);
			else if (ells > 1)
				size = sizeof(long long int);
			else if (ells == -1)
				size = sizeof(short int);
			else if (ells < -1)
				size = sizeof(char);
			else
				size = sizeof(int);
			if (input) {
				if (get_struct(proc->pid, arg, &arg, size, &err)) {
					tprintf(proc, "%s", err);
					goto next;
				}
				tprintf(proc, "&");
			}
			value = arg;
			if (size < sizeof(long long int))
				value &= (1ULL << (8 * size)) - 1;
			if (*fmt == 'u')
				tprintf(proc, "%llu", value);
			else if (*fmt == 'x')
				tprintf(proc, "%#llx", value);
			else if (*fmt == 'o')
				tprintf(proc, "%#llo", value);
			else
				tprintf(proc, "%lli", (long long int)value);
		}

	next:
		input = 0;
		ells = 0;
		i += 1;
	}

	tprintf(proc, ") ");
	va_end(ap);
}


void
print_systemcall(struct process *proc)
{
	unsigned long long int *args = proc->args;

#define UNDOCUMENTED(NAME) GENERIC_HANDLER(NAME)
#define UNIMPLEMENTED(NAME) GENERIC_HANDLER(NAME)
#define GENERIC_HANDLER(NAME)\
	case SYS_##NAME:\
		tprintf(proc, "%s(raw: %llu, %llu, %llu, %llu, %llu, %llu) ", #NAME,\
		        args[0], args[1], args[2], args[3], args[4], args[5]);\
		break
#define SIMPLE(NAME, FMT, RET_TYPE)\
	case SYS_##NAME:\
		printf_systemcall(proc, #NAME, (FMT));\
		proc->ret_type = (RET_TYPE);\
		break	
#define FORMATTERS(NAME, FMT, RET_TYPE, ...)\
	case SYS_##NAME:\
		printf_systemcall(proc, #NAME, (FMT), __VA_ARGS__);\
		proc->ret_type = (RET_TYPE);\
		break	

	proc->ret_type = Unknown;
	memset(proc->outputs, 0, sizeof(proc->outputs));

	/* TODO replace GENERIC_HANDLER with specific handlers */
	switch (proc->scall) {
	GENERIC_HANDLER(_sysctl);
	SIMPLE(accept, "ipp", Int); /* TODO output */
	FORMATTERS(accept4, "ipp1", Int, print_accept4_flags); /* TODO output */
	FORMATTERS(access, "s1", Int, print_access_flags);
	SIMPLE(acct, "s", Int);
	GENERIC_HANDLER(add_key);
	GENERIC_HANDLER(adjtimex);
	UNIMPLEMENTED(afs_syscall);
	SIMPLE(alarm, "u", UInt);
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
	FORMATTERS(clock_getres, "1>2", Int, print_clockid, print_timespec);
	FORMATTERS(clock_gettime, "1>2", Int, print_clockid, print_timespec);
	FORMATTERS(clock_nanosleep, "123>3", Int, print_clockid, print_clock_nanosleep_flags, print_timespec);
	FORMATTERS(clock_settime, "12", Int, print_clockid, print_timespec);
	GENERIC_HANDLER(clone);
	GENERIC_HANDLER(clone3);
	SIMPLE(close, "i", Int);
	GENERIC_HANDLER(connect);
	GENERIC_HANDLER(copy_file_range);
	SIMPLE(creat, "so", Int);
	SIMPLE(create_module, "slu", Ptr);
	FORMATTERS(delete_module, "s1", Int, print_delete_module_flags);
	SIMPLE(dup, "i", Int);
	SIMPLE(dup2, "ii", Int);
	FORMATTERS(dup3, "ii3", Int, print_dup3_flags);
	SIMPLE(epoll_create, "i", Int);
	FORMATTERS(epoll_create1, "1", Int, print_epoll_create1_flags);
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
	FORMATTERS(faccessat, "Fs12", Int, print_accept4_flags, print_faccessat_flags);
	GENERIC_HANDLER(fadvise64);
	GENERIC_HANDLER(fallocate);
	GENERIC_HANDLER(fanotify_init);
	GENERIC_HANDLER(fanotify_mark);
	SIMPLE(fchdir, "i", Int);
	SIMPLE(fchmod, "io", Int);
	FORMATTERS(fchmodat, "Fso1", Int, print_at_symlink_nofollow);
	SIMPLE(fchown, "iii", Int);
	FORMATTERS(fchownat, "Fsii1", Int, print_at_empty_path_at_symlink_nofollow);
	GENERIC_HANDLER(fcntl);
	SIMPLE(fdatasync, "i", Int);
	SIMPLE(fgetxattr, "is>mlu", Long);
	GENERIC_HANDLER(finit_module);
	GENERIC_HANDLER(flistxattr);
	GENERIC_HANDLER(flock);
	SIMPLE(fork, "", Int);
	SIMPLE(fremovexattr, "is", Int);
	UNDOCUMENTED(fsconfig);
	FORMATTERS(fsetxattr, "ismlu1", Int, print_setxattr_flags);
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
	FORMATTERS(getrandom, ">mlu1", Long, print_getrandom_flags);
	SIMPLE(getresgid, ">i>i>i", Int);
	SIMPLE(getresuid, ">i>i>i", Int);
	GENERIC_HANDLER(getrlimit);
	GENERIC_HANDLER(getrusage);
	SIMPLE(getsid, "i", Int);
	GENERIC_HANDLER(getsockname);
	GENERIC_HANDLER(getsockopt);
	SIMPLE(gettid, "", Int);
	GENERIC_HANDLER(gettimeofday);
	SIMPLE(getuid, "", Int);
	SIMPLE(getxattr, "ss>mlu", Long);
	GENERIC_HANDLER(init_module);
	FORMATTERS(inotify_add_watch, "is1", Int, print_inotify_add_watch_flags);
	SIMPLE(inotify_init, "", Int);
	FORMATTERS(inotify_init1, "1", Int, print_inotify_init1_flags);
	SIMPLE(inotify_rm_watch, "ii", Int);
	GENERIC_HANDLER(io_cancel);
	GENERIC_HANDLER(io_destroy);
	GENERIC_HANDLER(io_getevents);
	UNDOCUMENTED(io_pgetevents);
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
	FORMATTERS(kill, "i1", Int, print_signal_name);
	SIMPLE(lchown, "sii", Int);
	SIMPLE(lgetxattr, "ss>mlu", Long);
	SIMPLE(link, "ss", Int);
	FORMATTERS(linkat, "FsFs1", Int, print_at_empty_path_at_symlink_nofollow);
	SIMPLE(listen, "ii", Int);
	GENERIC_HANDLER(listxattr);
	GENERIC_HANDLER(llistxattr);
	GENERIC_HANDLER(lookup_dcookie);
	SIMPLE(lremovexattr, "ss", Int);
	FORMATTERS(lseek, "illi1", LLong, print_lseek_flag);
	FORMATTERS(lsetxattr, "ssmlu1", Int, print_setxattr_flags);
	SIMPLE(lstat, "sp", Int); /* TODO output */
	SIMPLE(madvise, "plui", Int); /* TODO flags */
	GENERIC_HANDLER(mbind);
	SIMPLE(membarrier, "ii", Int); /* TODO flags */
	FORMATTERS(memfd_create, "s1", Int, print_memfd_create_flags);
	GENERIC_HANDLER(migrate_pages);
	GENERIC_HANDLER(mincore);
	SIMPLE(mkdir, "so", Int);
	SIMPLE(mkdirat, "Fso", Int);
	GENERIC_HANDLER(mknod);
	GENERIC_HANDLER(mknodat);
	SIMPLE(mlock, "plu", Int);
	FORMATTERS(mlock2, "plu1", Int, print_mlock2_flags);
	FORMATTERS(mlockall, "1", Int, print_mlockall_flags);
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
	FORMATTERS(nanosleep, "1>1", Int, print_timespec);
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
	FORMATTERS(pipe, ">1", Int, print_int_pair);
	FORMATTERS(pipe2, ">12", Int, print_int_pair, print_pipe2_flags);
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
	SIMPLE(read, "i>mlu", Long);
	SIMPLE(readahead, "illilu", Long);
	SIMPLE(readlink, "s>mlu", Long);
	SIMPLE(readlinkat, "Fs>mlu", Long);
	GENERIC_HANDLER(readv);
	GENERIC_HANDLER(reboot);
	GENERIC_HANDLER(recvfrom);
	GENERIC_HANDLER(recvmmsg);
	GENERIC_HANDLER(recvmsg);
	GENERIC_HANDLER(remap_file_pages);
	SIMPLE(removexattr, "ss", Int);
	SIMPLE(rename, "ss", Int);
	SIMPLE(renameat, "FsFs", Int);
	FORMATTERS(renameat2, "FsFs1", Int, print_renameat2_flags);
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
	FORMATTERS(setxattr, "ssmlu1", Int, print_setxattr_flags);
	GENERIC_HANDLER(shmat);
	GENERIC_HANDLER(shmctl);
	GENERIC_HANDLER(shmdt);
	GENERIC_HANDLER(shmget);
	FORMATTERS(shutdown, "i1", Int, print_shutdown_flag);
	GENERIC_HANDLER(sigaltstack);
	GENERIC_HANDLER(signalfd);
	GENERIC_HANDLER(signalfd4);
	SIMPLE(socket, "iii", Int); /* TODO flags */
	FORMATTERS(socketpair, "iii>1", Int, print_int_pair); /* TODO flags */
	FORMATTERS(splice, "i&llii&llilu1", Long, print_splice_flags);
	GENERIC_HANDLER(stat);
	GENERIC_HANDLER(statfs);
	GENERIC_HANDLER(statx);
	SIMPLE(swapoff, "s", Int);
	SIMPLE(swapon, "si", Int); /* TODO flags */
	SIMPLE(symlink, "ss", Int);
	SIMPLE(symlinkat, "sFs", Int);
	SIMPLE(sync, "", Void);
	FORMATTERS(sync_file_range, "illilli1", Int, print_sync_file_range_flags);
	SIMPLE(syncfs, "i", Int);
	GENERIC_HANDLER(sysfs);
	GENERIC_HANDLER(sysinfo);
	GENERIC_HANDLER(syslog);
	GENERIC_HANDLER(tee);
	FORMATTERS(tgkill, "ii1", Int, print_signal_name);
	SIMPLE(time, ">lli", LLong);
	GENERIC_HANDLER(timer_create);
	GENERIC_HANDLER(timer_delete);
	GENERIC_HANDLER(timer_getoverrun);
	GENERIC_HANDLER(timer_gettime);
	GENERIC_HANDLER(timer_settime);
	GENERIC_HANDLER(timerfd_create);
	GENERIC_HANDLER(timerfd_gettime);
	GENERIC_HANDLER(timerfd_settime);
	GENERIC_HANDLER(times);
	FORMATTERS(tkill, "i1", Int, print_signal_name);
	SIMPLE(truncate, "slli", Int);
	UNIMPLEMENTED(tuxcall);
	SIMPLE(umask, "o", OInt);
	FORMATTERS(umount2, "s1", Int, print_umount2_flags);
	SIMPLE(uname, "p", Int); /* TODO output */
	SIMPLE(unlink, "s", Int);
	FORMATTERS(unlinkat, "Fs1", Int, print_unlinkat_flags);
	FORMATTERS(unshare, "1", Int, print_unshare_flags);
	SIMPLE(uselib, "s", Int);
	FORMATTERS(userfaultfd, "1", Int, print_userfaultfd_flags);
	GENERIC_HANDLER(ustat);
	GENERIC_HANDLER(utime);
	GENERIC_HANDLER(utimensat);
	GENERIC_HANDLER(utimes);
	SIMPLE(vfork, "", Int);
	SIMPLE(vhangup, "", Int);
	GENERIC_HANDLER(vmsplice);
	UNIMPLEMENTED(vserver);
	GENERIC_HANDLER(wait4);
	GENERIC_HANDLER(waitid);
	SIMPLE(write, "imlu", Long);
	GENERIC_HANDLER(writev);
	default:
		tprintf(proc, "syscall_0x%lx(raw: %llu, %llu, %llu, %llu, %llu, %llu) ",
		        (unsigned long int)proc->scall, args[0], args[1], args[2], args[3], args[4], args[5]);
		break;
	}
}


void
print_systemcall_exit(struct process *proc)
{
	size_t i, size;
	unsigned long long int value;
	char *str, buf[32];
	const char *err;

	if (proc->ret_type == Int || (proc->long_is_int && proc->ret_type == Long))
		tprintf(proc, "= %i", (int)proc->ret);
	else if (proc->ret_type == UInt || (proc->long_is_int && proc->ret_type == ULong))
		tprintf(proc, "= %u", (unsigned int)proc->ret);
	else if (proc->ret_type == OInt || (proc->long_is_int && proc->ret_type == OLong))
		tprintf(proc, "= %#o", (unsigned int)proc->ret);
	else if (proc->ret_type == XInt || (proc->long_is_int && proc->ret_type == XLong))
		tprintf(proc, "= %#x", (unsigned int)proc->ret);
	else if (proc->ret_type == Long)
		tprintf(proc, "= %li", (long int)proc->ret);
	else if (proc->ret_type == ULong)
		tprintf(proc, "= %lu", (unsigned long int)proc->ret);
	else if (proc->ret_type == OLong)
		tprintf(proc, "= %#lo", (unsigned long int)proc->ret);
	else if (proc->ret_type == XLong)
		tprintf(proc, "= %#lx", (unsigned long int)proc->ret);
	else if (proc->ret_type == LLong)
		tprintf(proc, "= %lli", (long long int)proc->ret);
	else if (proc->ret_type == ULLong)
		tprintf(proc, "= %llu", (unsigned long long int)proc->ret);
	else if (proc->ret_type == OLLong)
		tprintf(proc, "= %#llo", (unsigned long long int)proc->ret);
	else if (proc->ret_type == XLLong)
		tprintf(proc, "= %#llx", (unsigned long long int)proc->ret);
	else if (proc->ret_type == Ptr && (long long int)proc->ret >= 0 && proc->ptr_is_int)
		tprintf(proc, "= %#x", (unsigned int)proc->ret);
	else if (proc->ret_type == Ptr && (long long int)proc->ret >= 0)
		tprintf(proc, "= %#llx", proc->ret);
	else
		tprintf(proc, "= %lli", (long long int)proc->ret);

	if (RETURN_IS_ERROR(proc->ret)) {
		tprintf(proc, " (%s: %s)\n", get_errno_name(-(int)proc->ret), strerror(-(int)proc->ret));
	} else {
		tprintf(proc, "\n");
		for (i = 0; i < 6; i++) {
			if (!proc->args[i] || !proc->outputs[i].fmt)
				continue;
			tprintf(proc, "        Output to parameter %zu: ", i + 1);
			switch (proc->outputs[i].fmt) {

			case 'p':
				if (proc->ptr_is_int) {
					if (get_struct(proc->pid, proc->args[i], buf, sizeof(int), &err))
						tprintf(proc, "%s\n", err);
					else if (*(unsigned int *)buf)
						tprintf(proc, "%#x\n", *(unsigned int *)buf);
					else
						tprintf(proc, "NULL\n");
				} else {
					if (get_struct(proc->pid, proc->args[i], buf, sizeof(long int), &err))
						tprintf(proc, "%s\n", err);
					else if (*(unsigned long int *)buf)
						tprintf(proc, "%#lx\n", *(unsigned long int *)buf);
					else
						tprintf(proc, "NULL\n");
				}
				break;

			case 'm':
				value = proc->args[i + 1] < proc->ret ? proc->args[i + 1] : proc->ret;
				str = get_escaped_memory(proc->pid, proc->args[i], (size_t)value, &err);
				tprintf(proc, "%s\n", str ? str : err);
				free(str);
				break;

			case '1': case '2': case '3': case '4': case '5': case '6':
				proc->outputs[i].func(proc, i);
				tprintf(proc, "\n");
				break;

			default:
				/* .ells is adjust for .long_is_int when set */
				if (proc->outputs[i].ells == 1)
					size = sizeof(unsigned long int);
				else if (proc->outputs[i].ells > 1)
					size = sizeof(unsigned long long int);
				else if (proc->outputs[i].ells == -1)
					size = sizeof(unsigned short int);
				else if (proc->outputs[i].ells < -1)
					size = sizeof(unsigned char);
				else
					size = sizeof(unsigned int);
				if (get_struct(proc->pid, proc->args[i], buf, size, &err)) {
					tprintf(proc, "%s\n", err);
					break;
				}
				if (proc->outputs[i].ells == 1)
					value = *(unsigned long int *)buf;
				else if (proc->outputs[i].ells > 1)
					value = *(unsigned long long int *)buf;
				else if (proc->outputs[i].ells == -1)
					value = *(unsigned short int *)buf;
				else if (proc->outputs[i].ells < -1)
					value = *(unsigned char *)buf;
				else
					value = *(unsigned long long int *)buf;
				if (proc->outputs[i].fmt == 'u')
					tprintf(proc, "%llu\n", i + 1, value);
				else if (proc->outputs[i].fmt == 'x')
					tprintf(proc, "%#llx\n", i + 1, value);
				else if (proc->outputs[i].fmt == 'o')
					tprintf(proc, "%#llo\n", i + 1, value);
				else
					tprintf(proc, "%lli\n", i + 1, (long long int)value);
				break;
			}
		}
	}
}
