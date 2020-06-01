#include <unistd.h>

int
main(void)
{
	switch (vfork()) {
	case -1:
		return -1;
	case 0:
		_exit(2);
	default:
		return 1;
	}
}
