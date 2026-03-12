int main (string[] args) {
	try {
		var r2 = new R2Pipe.sync ("/bin/ls");
		try {
			stdout.printf ("%s\n", r2.cmdSync ("x"));
			stdout.printf ("%s\n", r2.cmdSync ("pd 20"));
		} finally {
			try {
				r2.close ();
			} catch (Error e) {
			}
		}

		var loop = new MainLoop ();
		var r2p = new R2Pipe ("/bin/ls");
		r2p.cmd ("pi 4", (x) => {
			stdout.printf ("DISASM((%s))\n", x);
			try {
				r2p.cmd ("ie", (y) => {
					stdout.printf ("entry((%s))\n", y);
					loop.quit ();
				});
			} catch (Error e) {
				stderr.printf ("%s\n", e.message);
				loop.quit ();
			}
		});
		loop.run ();
		try {
			r2p.close ();
		} catch (Error e) {
		}
		return 0;
	} catch (Error e) {
		stderr.printf ("%s\n", e.message);
		return 1;
	}
}
