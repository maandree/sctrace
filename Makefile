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
	arch-x86-64.h\
	arg.h\
	common.h\
	list-errnos.h\
	list-signums.h

all: sctrace
$(OBJ): $(@:.o=.c) $(HDR)

sctrace: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

.c.o:
	$(CC) -c -o $@ $< $(CPPFLAGS) $(CFLAGS)

list-errnos.h:
	printf '#define LIST_ERRNOS(_)\\\n\t' > $@
	cat /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h \
		| sed 's/\/\/.*$$//' | tr -d '$$' | sed 's/\*\//\$$/g' | sed 's/\/\*[^$$]*\$$//g' \
		| sed -n '/^[ \t]*#[ \t]*define[ \t].*[ \t][0-9]*[ \t]*$$/s/^[ \t#]*define[ \t]*\([^ \t]*\).*$$/_(\1)/p' \
		| sort | uniq | tr '\n' '#' | sed 's/#_/\\\n\t_/g' | tr '#' '\n' >> $@

list-signums.h:
	printf '#define LIST_SIGNUMS(_)\\\n\t' > $@
	cat /usr/include/bits/signum.h /usr/include/bits/signum-generic.h \
		| sed 's/\/\/.*$$//' | tr -d '$$' | sed 's/\*\//\$$/g' | sed 's/\/\*[^$$]*\$$//g' \
		| sed -n '/^[ \t]*#[ \t]*define[ \t][^_]*[ \t][0-9]*[ \t]*$$/s/^[ \t#]*define[ \t]*\([^ \t]*\).*$$/_(\1)/p' \
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
