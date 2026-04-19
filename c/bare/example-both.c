/* Example: one binary that can use either backend at runtime. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define R2P_ENABLE_DLOPEN 1
#define R2P_ENABLE_SPAWN  1
#include "r2pipe.inc.c"

static void run(R2Pipe *r, const char *cmd) {
	char *out = r2p_cmd(r, cmd);
	if (out) {
		printf("> %s\n%s", cmd, out);
		free(out);
	}
}

static void usage(const char *prog) {
	fprintf(stderr,
		"usage: %s [dlopen|spawn] <file> [flags]\n"
		"  flags: quoted string, e.g. \"-d -aaa\"\n",
		prog);
}

int main(int argc, char **argv) {
	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}
	int mode = !strcmp(argv[1], "dlopen") ? R2P_DLOPEN : R2P_SPAWN;
	const char *file  = argv[2];
	const char *flags = (argc > 3) ? argv[3] : "";

	R2Pipe *r = r2p_open(mode, file, flags);
	if (!r) {
		return 1;
	}
	run(r, "?V");
	run(r, "pd 3 @ entry0");
	r2p_close(r);
	return 0;
}
