#include <signal.h>

int
main(void)
{
	raise(SIGTERM);
	return 0;
}
