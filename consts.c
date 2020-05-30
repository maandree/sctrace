/* See LICENSE file for copyright and license details. */
#include "common.h"


const char *
get_errno_name(int err)
{
	static char buf[3 * sizeof(err) + 2];

#define X(N) if (err == N) return #N;
	LIST_ERRNOS(X)
#undef X

	sprintf(buf, "%i", err);
	return buf;
}
