CFLAGS+=$(shell pkg-config --cflags r_socket)
LDFLAGS+=$(shell pkg-config --libs r_socket)

TESTS=test-pipe test-pipe2 test-spawn

all: $(TESTS)

test-pipe:
	$(CC) -o test-pipe test-pipe.c $(CFLAGS) $(LDFLAGS)
	r2 -q -c '#!pipe ./test-pipe' /bin/ls

test-pipe2:
	$(CC) -o test-pipe2 test-pipe2.c $(CFLAGS) $(LDFLAGS)
	#r2 -q -c '#!pipe ./test-pipe2' /bin/ls
	./test-pipe2

test-spawn:
	$(CC) -o test-spawn test-spawn.c $(CFLAGS) $(LDFLAGS)
	./test-spawn

clean:
	rm -f $(TESTS)
	rm -f a.out

.PHONY: $(TESTS)

