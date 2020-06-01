#include <signal.h>
#include <unistd.h>

int
main(void)
{
	return kill(getpid(), SIGSTOP);
}
