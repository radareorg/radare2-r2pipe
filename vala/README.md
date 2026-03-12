r2pipe.vala
===========

Vala binding for the `r2pipe` protocol.

Supported transports
--------------------

- spawn: `new R2Pipe.sync ("/bin/ls")`
- HTTP: `new R2Pipe.sync ("http://127.0.0.1:9090")`
- in-process pipe: `new R2Pipe.sync ()` or `new R2Pipe.sync ("#!pipe")`
- JSON parsing: `cmdj("ij")`

Build
-----

Requirements:

- `valac`
- `gio-2.0`
- `gio-unix-2.0`
- `json-glib-1.0`
- `radare2` in `PATH` for spawn/tests

Build the example program and static library:

```sh
make -C vala
```

Build the test binary:

```sh
make -C vala test-vala
```

Run the transport tests:

```sh
make -C vala test
```

Install the library artifacts:

```sh
make -C vala install
```

Usage
-----

Spawn a local `radare2`:

```vala
try {
	var r2 = new R2Pipe.sync ("/bin/ls");
	stdout.printf ("%s\n", r2.cmdSync ("?V"));
	r2.close ();
} catch (Error e) {
	stderr.printf ("%s\n", e.message);
}
```

Parse JSON:

```vala
try {
	var r2 = new R2Pipe.sync ("/bin/ls");
	var info = r2.cmdj ("ij");
	var obj = info.get_object ();
	stdout.printf ("%s\n", obj.get_string_member ("core"));
	r2.close ();
} catch (Error e) {
	stderr.printf ("%s\n", e.message);
}
```

Connect over HTTP:

```sh
r2 -q0 -e http.bind=127.0.0.1 -e http.port=9090 -c '=H' /bin/ls
```

```vala
try {
	var r2 = new R2Pipe.sync ("http://127.0.0.1:9090");
	stdout.printf ("%s\n", r2.cmdSync ("?V"));
	r2.close ();
} catch (Error e) {
	stderr.printf ("%s\n", e.message);
}
```

Use `#!pipe` from inside `r2`:

```sh
r2 -q0 -c '#!pipe ./your-vala-binary' /bin/ls
```

```vala
try {
	var r2 = new R2Pipe.sync ();
	stdout.printf ("%s\n", r2.cmdSync ("?e hello-from-r2"));
} catch (Error e) {
	stderr.printf ("%s\n", e.message);
}
```
