.POSIX:

BIN_64 =\
	abort.64\
	abort-nodump.64\
	cont.64\
	exec.64\
	exit.64\
	fork.64\
	fork-many.64\
	fork-sleep.64\
	fork-stop.64\
	kill.64\
	raise.64\
	siginfo.64\
	signal.64\
	signal-interrupt.64\
	stop.64\
	threads.64\
	tstp.64\
	vfork.64\
	vfork-exec.64

BIN_32 = $(BIN_64:.64=.32)

all: $(BIN_64) $(BIN_32)
$(BIN_64): $(@:.64=.c)
$(BIN_32): $(@:.32=.c)

.c.64:
	$(CC) -static -pthread -Og -g -o $@ $< -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE

.c.32:
	$(CC) -m32 -static -pthread -Og -g -o $@ $< -D_XOPEN_SOURCE=700 -D_DEFAULT_SOURCE

clean:
	-rm -f -- $(BIN_64) $(BIN_32)

.SUFFIXES:
.SUFFIXES: .32 .64 .c

.PHONY: all clean
