/* See LICENSE file for copyright and license details. */
#include "common.h"


static void
print_clockid(struct process *proc, size_t arg_index) /* TODO */
{
	tprintf(proc, "%li", (long int)proc->args[arg_index]);
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
printf_systemcall(struct process *proc, const char *scall, const char *fmt, ...)
{
	typedef char *(*Function)(struct process *proc, size_t arg_index);
	Function funcs[6];
	size_t i, nfuncs = 0, func, len;
	unsigned long long int *args = proc->args;
	int ells = 0;
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
		if (i)
			tprintf(proc, ", ");
		if (*fmt == 'p') {
			if (args[i])
				tprintf(proc, "%p", (void *)args[i]);
			else
				tprintf(proc, "NULL");
		} else if (*fmt >= '1' && *fmt <= '6') {
			func = (size_t)(*fmt - '0');
			while (nfuncs < func)
				funcs[nfuncs++] = va_arg(ap, Function);
			funcs[func - 1](proc, i);
		} else if (*fmt == 's') {
			str = get_string(proc->pid, args[i], &len, &err);
			str = escape_memory(str, len);
			tprintf(proc, "%s", str ? str : err);
			free(str);
		} else if (*fmt == 'm') {
			str = escape_memory(get_memory(proc->pid, args[i], (size_t)args[i + 1], &err), (size_t)args[i + 1]);
			tprintf(proc, "%s", str ? str : err);
			free(str);
		} else if (*fmt == 'F') {
			if ((int)args[i] == AT_FDCWD)
				tprintf(proc, "AT_FDCWD");
			else
				tprintf(proc, "%i", (int)args[i]);
		} else if (*fmt == 'u') {
			if (ells == 1)
				tprintf(proc, "%lu", (unsigned long int)args[i]);
			else if (ells > 1)
				tprintf(proc, "%llu", (unsigned long long int)args[i]);
			else
				tprintf(proc, "%u", (unsigned int)args[i]);
		} else if (*fmt == 'x') {
			if (ells == 1)
				tprintf(proc, "%#lx", (unsigned long int)args[i]);
			else if (ells > 1)
				tprintf(proc, "%#llx", (unsigned long long int)args[i]);
			else
				tprintf(proc, "%#x", (unsigned int)args[i]);
		} else if (*fmt == 'o') {
			if (ells == 1)
				tprintf(proc, "%#lo", (unsigned long int)args[i]);
			else if (ells > 1)
				tprintf(proc, "%#llo", (unsigned long long int)args[i]);
			else
				tprintf(proc, "%#o", (unsigned int)args[i]);
		} else {
			if (ells == 1)
				tprintf(proc, "%li", (long int)args[i]);
			else if (ells > 1)
				tprintf(proc, "%lli", (long long int)args[i]);
			else
				tprintf(proc, "%i", (int)args[i]);
		}
		ells = 0;
		i += 1;
	}
	tprintf(proc, ") ");
	va_end(ap);
}


void
print_systemcall(struct process *proc)
{
	char buf1[128], *p, *buf;
	unsigned long int flags;
	unsigned long long int *args = proc->args;

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

	/* TODO replace GENERIC_HANDLER with specific handlers */
	switch (proc->scall) {
	GENERIC_HANDLER(_sysctl);
	SIMPLE(accept, "ipp", Int); /* TODO output */
	case SYS_accept4: /* TODO output */
		FLAGS_BEGIN(buf1, args[3]);
		FLAGS_ADD(SOCK_NONBLOCK);
		FLAGS_ADD(SOCK_CLOEXEC);
		FLAGS_END("%#x", unsigned int);
		tprintf(proc, "accept4(%i, %p, %p, %s) ", (int)args[0], (void *)args[1], (void *)args[2], &buf1[1]);
		proc->ret_type = Int;
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
	FORMATTERS(clock_getres, "1p", Int, print_clockid); /* TODO output */
	FORMATTERS(clock_gettime, "1p", Int, print_clockid); /* TODO output */
	FORMATTERS(clock_nanosleep, "1i2p", Int, print_clockid, print_timespec); /* TODO output, flags */
	FORMATTERS(clock_settime, "12", Int, print_clockid, print_timespec);
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
		tprintf(proc, "epoll_create1(%s) ", &buf1[1]);
		proc->ret_type = Int;
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
	FORMATTERS(nanosleep, "1p", Int, print_timespec); /* TODO output */
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
		tprintf(proc, "syscall_0x%lx(raw: %llu, %llu, %llu, %llu, %llu, %llu) ",
		        (unsigned long int)proc->scall, args[0], args[1], args[2], args[3], args[4], args[5]);
		break;
	}
}


void
print_systemcall_exit(struct process *proc)
{
	if (proc->ret_type == Int)
		tprintf(proc, "= %i", (int)proc->ret);
	else if (proc->ret_type == UInt)
		tprintf(proc, "= %u", (unsigned int)proc->ret);
	else if (proc->ret_type == OInt)
		tprintf(proc, "= %#o", (unsigned int)proc->ret);
	else if (proc->ret_type == XInt)
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
	else if (proc->ret_type == Ptr && (long long int)proc->ret >= 0)
		tprintf(proc, "= %p", (void *)proc->ret);
	else
		tprintf(proc, "= %li", (long int)proc->ret);

	if ((unsigned long long int)proc->ret > -(unsigned long long int)PAGE_SIZE)
		tprintf(proc, " (%s: %s)", get_errno_name(-(int)proc->ret), strerror(-(int)proc->ret));

	tprintf(proc, "\n");
}
