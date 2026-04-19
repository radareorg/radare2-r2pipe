CFLAGS  ?= -Wall -Wextra -O2
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
LDFLAGS_DLOPEN = -ldl
endif
ifeq ($(UNAME_S),Darwin)
LDFLAGS_DLOPEN =
endif

BINS = example-spawn example-dlopen example-both

all: $(BINS)

example-spawn: example-spawn.c r2pipe.inc.c
	$(CC) $(CFLAGS) -o $@ example-spawn.c

example-dlopen: example-dlopen.c r2pipe.inc.c
	$(CC) $(CFLAGS) -o $@ example-dlopen.c $(LDFLAGS_DLOPEN)

example-both: example-both.c r2pipe.inc.c
	$(CC) $(CFLAGS) -o $@ example-both.c $(LDFLAGS_DLOPEN)

test: test-spawn test-dlopen

test-spawn: example-spawn
	./example-spawn /bin/ls ""

test-dlopen: example-dlopen
	./example-dlopen /bin/ls ""

clean:
	rm -f $(BINS) *.o

.PHONY: all clean test test-spawn test-dlopen
