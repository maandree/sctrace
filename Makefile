.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

all: sctrace

sctrace: sctrace.c arg.h list-errnos.h
	$(CC) -o $@ $@.c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS)

list-errnos.h:
	printf '#define LIST_ERRNOS(_)\\\n\t' > $@
	cat /usr/include/asm-generic/errno.h /usr/include/asm-generic/errno-base.h \
		| sed 's/\/\/.*$$//' | tr -d '$$' | sed 's/\*\//\$$/g' | sed 's/\/\*[^$$]*\$$//g' \
		| sed -n '/^[ \t]*#[ \t]*define[ \t].*[ \t][0-9]*[ \t]*$$/s/^[ \t#]*define[ \t]*\([^ \t]*\).*$$/_(\1)/p' \
		| sort | uniq | tr '\n' '#' | sed 's/#_/\\\n\t_/g' | tr '#' '\n' >> $@

install: sctrace
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	cp -- sctrace "$(DESTDIR)$(PREFIX)/bin"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/sctrace"

clean:
	-rm -f -- *.o list-errnos.h sctrace

.PHONY: all install uninstall clean
