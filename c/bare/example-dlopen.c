/* Example: load libr_core and drive it directly (no subprocess). */
#include <stdio.h>
#include <stdlib.h>

#define R2P_ENABLE_DLOPEN 1
#define R2P_ENABLE_SPAWN  0
#include "r2pipe.inc.c"

static void run(R2Pipe *r, const char *cmd) {
	char *out = r2p_cmd(r, cmd);
	if (out) {
		printf("> %s\n%s", cmd, out);
		free(out);
	}
}

int main(int argc, char **argv) {
	const char *file = (argc > 1) ? argv[1] : "/bin/ls";
	const char *flags = (argc > 2) ? argv[2] : "";

	R2Pipe *r = r2p_open(R2P_DLOPEN, file, flags);
	if (!r) {
		fprintf(stderr, "cannot load libr_core\n");
		return 1;
	}
	run(r, "?e Hello World");
	run(r, "i~format");
	run(r, "pd 5 @ entry0");
	r2p_close(r);
	return 0;
}
