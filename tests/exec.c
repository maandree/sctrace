#include <unistd.h>

int
main(void)
{
	return execlp("printf", "printf", "hello world\n", NULL);
}
