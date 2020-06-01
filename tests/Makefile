.POSIX:

BIN =\
	abort.t\
	cont.t\
	exec.t\
	exit.t\
	fork.t\
	fork-stop.t\
	kill.t\
	raise.t\
	siginfo.t\
	signal.t\
	stop.t\
	threads.t\
	tstp.t\
	vfork.t\
	vfork-exec.t

all: $(BIN)
$(BIN): $(@:.t=.c)

.c.t:
	$(CC) -static -pthread -Og -g -o $@ $< -D_XOPEN_SOURCE=700

clean:
	-rm -f -- $(BIN)

.SUFFIXES:
.SUFFIXES: .t .c

.PHONY: all clean
