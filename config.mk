PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = cc

ERRNO_HDRS  = /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h
SIGNUM_HDRS = /usr/include/bits/signum.h /usr/include/bits/signum-generic.h

CPPFLAGS = -D_XOPEN_SOURCE=700 -D_GNU_SOURCE
CFLAGS   = -std=c11 -Wall -Og -g
LDFLAGS  =
