
var r2 = new R2Pipe.sync("/bin/ls");
stdout.printf ("%s\n", r2.cmd("x"));
stdout.printf ("%s\n", r2.cmd("pd 20"));

MainLoop loop = new MainLoop ();
var r2p = new R2Pipe ("/bin/ls");
r2p.cmd ("pi 4", (x) => {
	stdout.printf ("DISASM((%s))\n", x);
	r2p.cmd ("ie", (x) => {
		stdout.printf ("entry((%s))\n", x);
		r2p.cmd ("q");
	});
});

/*
ChildWatch.add (r2p.child_pid, (pid, status) => {
	// Triggered when the child indicated by child_pid exits
	Process.close_pid (pid);
	loop.quit ();
});
loop.run ();
*/
