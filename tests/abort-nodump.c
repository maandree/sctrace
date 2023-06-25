#include <sys/prctl.h>
#include <stdlib.h>

int
main(void)
{
	prctl(PR_SET_DUMPABLE, 0);
	abort();
}
