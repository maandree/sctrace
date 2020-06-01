#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const char *
strsigcode(int code)
{
	switch (code) {
	case SI_USER:
		return "SIG_USER";
	case SI_KERNEL:
		return "SIG_KERNEL";
	case SI_QUEUE:
		return "SIG_QUEUE";
	case SI_TIMER:
		return "SIG_TIMER";
	case SI_MESGQ:
		return "SIG_MESGQ";
	case SI_ASYNCIO:
		return "SIG_ASYNCIO";
	case SI_SIGIO:
		return "SIG_SIGIO";
	case SI_TKILL:
		return "SIG_TKILL";
	default:
		return "???";
	}
}

void
handler(int signo, siginfo_t *info, void *frame)
{
	(void) signo;
	(void) frame;
	fprintf(stderr, ".si_signo: %i (%s)\n", info->si_signo, strsignal(info->si_signo));
	fprintf(stderr, ".si_code:  %i (%s)\n", info->si_code, strsigcode(info->si_code));
	fprintf(stderr, ".si_errno: %i\n", info->si_errno);
	if (info->si_code == SI_USER || info->si_code == SI_TKILL || info->si_code == SI_QUEUE) {
		fprintf(stderr, ".si_pid: %ju\n", info->si_pid);
		fprintf(stderr, ".si_uid: %ju\n", info->si_uid);
		if (info->si_code == SI_QUEUE) {
			fprintf(stderr, ".si_value.sival_int: %i\n", info->si_value.sival_int);
			fprintf(stderr, ".si_value.sival_ptr: %p\n", info->si_value.sival_ptr);
		}
	}
	_exit(1);
}

int
main(void)
{
	static union sigval value;
	static struct sigaction sa;
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGRTMAX, &sa, 0);
	value.sival_int = 1444;
	sigqueue(getpid(), SIGRTMAX, value);
	pause();
	return 0;
}
