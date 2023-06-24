/* See LICENSE file for copyright and license details. */
#include <linux/elf.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h> /* after <sys/ptrace.h> */
#include <sys/syscall.h>
#include <sys/user.h>

#ifndef ERESTARTSYS
# define ERESTARTSYS 512
# define ALSO_ERESTARTSYS
#endif
#ifndef ERESTARTNOINTR
# define ERESTARTNOINTR 513
# define ALSO_ERESTARTNOINTR
#endif
#ifndef ERESTARTNOHAND
# define ERESTARTNOHAND 514
# define ALSO_ERESTARTNOHAND
#endif
#ifndef ERESTART_RESTARTBLOCK
# define ERESTART_RESTARTBLOCK 516
# define ALSO_ERESTART_RESTARTBLOCK
#endif

#define RETURN_IS_ERROR(RET)\
	((RET) > -(unsigned long long int)PAGE_SIZE) /* Don't know the actual limit, but this seems safe */

#if defined(__x86_64__) && !defined(__IPL32__)
# include "x86-64.h"
#else
# error "This program is only implemented for x86-64 on Linux"
#endif

#if defined(__sparc__)
# define REGARGS(a, b) b, a
#else
# define REGARGS(a, b) a, b
#endif
