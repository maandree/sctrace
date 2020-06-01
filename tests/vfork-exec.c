#include <unistd.h>

int
main(int argc, char *argv[], char *envp[])
{
	(void) argc;
	argv = (void *)(const char *[]){"/usr/bin/sleep", "1", NULL};
	switch (vfork()) {
	case -1:
		return -1;
	case 0:
		execve("", argv, envp);
		execve(*argv, argv, envp);
		_exit(2);
	default:
		return 1;
	}
}
