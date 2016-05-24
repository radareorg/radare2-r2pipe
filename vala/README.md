r2pipe.vala
===========

C/Vala glib-based API for use radare2 via the r2pipe protocol.

Installation
------------

You can type `make install` or `make uninstall` here.

Example:
-------

```
var r2 = new R2Pipe.sync("/bin/ls");
print (r2.cmd("?e Hello World"));
```

Compile this example with this:
```
$ valac --pkg r2pipe main.vala
$ ./main
```

Or just run it in a shot:

```
$ vala --pkg=r2pipe main.vala
```
