CFLAGS+=$(shell pkg-config --cflags r_socket)
LDFLAGS+=$(shell pkg-config --libs r_socket)

all: test-pipe test-spawn

test-pipe:
	$(CC) -o test-pipe $(CFLAGS) $(LDFLAGS) test-pipe.c
	r2 -q -c '#!pipe ./test-pipe' /bin/ls

test-spawn:
	$(CC) -o test-spawn $(CFLAGS) $(LDFLAGS) test-spawn.c
	echo q | ./test-spawn

clean:
	rm -f test-spawn test-pipe
	rm -f a.out

.PHONY: test-pipe test-spawn
