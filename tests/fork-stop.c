#include <signal.h>
#include <unistd.h>

int
main(void)
{
	if (fork() == -1)
		return -1;
	return kill(getpid(), SIGSTOP);
}
