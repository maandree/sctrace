/* See LICENSE file for copyright and license details. */
#include "common.h"


const char *
get_errno_name(int err)
{
	static char buf[3 * sizeof(err) + 2];

#define X(N) if (err == N) return #N;
	LIST_ERRNOS(X)
#ifdef ALSO_ERESTARTSYS
	X(ERESTARTSYS)
#endif
#ifdef ALSO_ERESTARTNOINTR
	X(ERESTARTNOINTR)
#endif
#ifdef ALSO_ERESTARTNOHAND
	X(ERESTARTNOHAND)
#endif
#ifdef ALSO_ERESTART_RESTARTBLOCK
	X(ERESTART_RESTARTBLOCK)
#endif
#undef X

	sprintf(buf, "%i", err);
	return buf;
}
