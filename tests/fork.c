#include <time.h>
#include <unistd.h>

int
main(void)
{
	struct timespec ts = {0, 100000000L};
	switch (fork()) {
	case -1:
		return -1;
	case 0:
		return 2;
	default:
		nanosleep(&ts, NULL);
		return 1;
	}
}
