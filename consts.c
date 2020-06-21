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


const char *
get_signum_name(int sig)
{
	static char buf[3 * sizeof(sig) + 2];
	int above_low, below_high;

#define X(N) if (sig == N) return #N;
	LIST_SIGNUMS(X)
#undef X

	if (SIGRTMIN <= sig && sig <= SIGRTMAX) {
		above_low = sig - SIGRTMIN;
		below_high = SIGRTMAX - sig;
		if (!above_low)
			return "SIGRTMIN";
		if (!below_high)
			return "SIGRTMAX";
		if (above_low <= below_high)
			sprintf(buf, "SIGRTMIN+%i", above_low);
		else
			sprintf(buf, "SIGRTMAX-%i", below_high);
		return buf;
	}

	sprintf(buf, "%i", sig);
	return buf;
}
