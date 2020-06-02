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
	signal(SIGINT, interrupt);
	kill(getpid(), SIGINT);
	nanosleep(&ts, NULL);
	write(-1, "qwerty\n", 7);
	return 0;
}
