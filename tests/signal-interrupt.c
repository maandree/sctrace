#include <signal.h>
#include <time.h>
#include <unistd.h>

static void
interrupt()
{
	write(-2, "xyzzy\n", 6);
}

int
main(void)
{
	struct timespec ts = {0, 100000000L};
	pid_t pid = getpid();
	signal(SIGINT, interrupt);
	if (fork() == 0) {
		ts.tv_nsec /= 2;
		nanosleep(&ts, NULL);
		kill(pid, SIGINT);
	} else {
		nanosleep(&ts, NULL);
		write(-1, "qwerty\n", 7);
	}
	return 0;
}
