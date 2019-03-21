#include <r_socket.h>

static void r2cmd(R2Pipe *r2, const char *cmd) {
	char *msg = r2pipe_cmd (r2, cmd);
	if (msg) {
		printf ("%s\n", msg);
		free (msg);
	}
}

int main() {
	R2Pipe *r2 = r2pipe_open (NULL);
	if (r2) {
		r2cmd (r2, "?e Hello World");
		r2cmd (r2, "x");
		r2cmd (r2, "?e Hello World");
		r2pipe_close (r2);
		return 0;
	}
	return 1;
}
