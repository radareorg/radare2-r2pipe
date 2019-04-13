/* Simple r2pipe implementation in C for writing r2pipe shellscripts */
/* Copyleft -- pancake 2019 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void r2cmd(int in, int out, const char *cmd) {
	write (out, cmd, strlen (cmd) + 1);
	write (out, "\n", 1);
	int n;
	int bufsz = (1024 * 1024 * 2);
	unsigned char *buf = malloc (bufsz);
	while (1) {
		int n = read (in, buf, bufsz);
		int len = strlen ((const char *)buf);
		n = len;
		if (n < 1) {
			break;
		}
		write (1, buf, n);
		if (n != sizeof (buf)) {
			break;
		}
	}
	free (buf);
	write(1, "\n", 1);
}

int main(int argc, char **argv) {
	int i;
	int in = atoi (getenv ("R2PIPE_IN"));
	int out = atoi (getenv ("R2PIPE_OUT"));
	for (i = 1; i < argc; i++) {
		r2cmd (in, out, argv[i]);
	}
	return 0;
}
