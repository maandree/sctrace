.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OBJ =\
	consts.o\
	memory.o\
	print.o\
	process.o\
	sctrace.o\
	util.o

HDR =\
	linux/os.h\
	linux/x86-64.h\
	arg.h\
	common.h\
	list-errnos.h\
	list-signums.h

S = [:space:]

all: sctrace
$(OBJ): $(@:.o=.c) $(HDR)

sctrace: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

list-errnos.h:
	printf '#define LIST_ERRNOS(_)\\\n\t' > $@
	cat $(ERRNO_HDRS) | tr '\n' '\0' \
		| sed 's/\/\/.*$$//' | tr -d '$$' | sed 's/\*\//\$$/g' | sed 's/\/\*[^$$]*\$$//g' | tr '\0' '\n' \
		| sed -n '/^[$S]*#[$S]*define[$S].*[$S][0-9]*[$S]*$$/s/^[$S#]*define[$S]*\([^$S]*\).*$$/_(\1)/p' \
		| sort | uniq | tr '\n' '#' | sed 's/#_/\\\n\t_/g' | tr '#' '\n' >> $@

list-signums.h:
	printf '#define LIST_SIGNUMS(_)\\\n\t' > $@
	cat $(SIGNUM_HDRS) | tr '\n' '\0' \
	        | sed 's/\/\/.*$$//' | tr -d '$$' | sed 's/\*\//\$$/g' | sed 's/\/\*[^$$]*\$$//g' | tr '\0' '\n' \
		| sed -n '/^[$S]*#[$S]*define[$S][^_]*[$S][0-9]*[$S]*$$/s/^[$S#]*define[$S]*\([^$S]*\).*$$/_(\1)/p' \
		| grep -v 'SIG\(UNUSED\|RTMIN\|RTMAX\|STKSZ\)' | grep '(SIG' \
		| sort | uniq | tr '\n' '#' | sed 's/#_/\\\n\t_/g' | tr '#' '\n' >> $@

install: sctrace
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man1"
	cp -- sctrace "$(DESTDIR)$(PREFIX)/bin"
	cp -- sctrace.1 "$(DESTDIR)$(MANPREFIX)/man1"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/sctrace"
	-rm -f -- "$(DESTDIR)$(MANPREFIX)/man1/sctrace.1"

clean:
	-rm -f -- *.o list-*.h sctrace

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all install uninstall clean
