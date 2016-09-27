#include <r_socket.h>

static void r2cmd(R2Pipe *r2, const char *cmd) {
	char *msg = r2p_cmd (r2, cmd);
	if (msg) {
		printf ("%s\n", msg);
		free (msg);
	}
}

int main() {
	// R2Pipe *r2 = r2p_open ("/bin/ls");
	R2Pipe *r2 = r2p_open ("r2 -q0 /bin/ls");
	if (r2) {
		r2cmd (r2, "?e Hello World");
		r2cmd (r2, "x");
		r2cmd (r2, "?e Hello World");
		r2cmd (r2, "pd 20");
		r2p_close (r2);
		return 0;
	}
	return 1;
}
