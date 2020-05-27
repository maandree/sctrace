.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

all: sctrace

sctrace: sctrace.c arg.h
	$(CC) -o $@ $@.c $(CPPFLAGS) $(CFLAGS) $(LDFLAGS)

install: sctrace
	mkdir -p -- "$(DESTDIR)$(PREFIX)/bin"
	cp -- sctrace "$(DESTDIR)$(PREFIX)/bin"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/bin/sctrace"

clean:
	-rm -f -- *.o sctrace

.PHONY: all install uninstall clean
