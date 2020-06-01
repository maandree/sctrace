#include <unistd.h>

int
main(void)
{
	switch (fork()) {
	case -1:
		return -1;
	case 0:
		return 2;
	default:
		usleep(100000U);
		return 1;
	}
}
