R2PIPE.SWIFT
============

Swift 2.0 API to communicate with a radare2 session using r2pipe.

Author: pancake <pancake@nopcode.org>

Description
-----------
This API provides support to run commands in r2 using different channels:

* http
* spawn
* pipe

And can be accessed:

* sync
* async

And optionally supports to parse JSON

Example
-------

This example shows how to use the sync and async APIs for HTTP:

```swift
if let r2p = R2Pipe("http://cloud.radare.org/cmd/") {
	if let str = r2p.cmdSync ("?V") {
		print ("Version: \(str)");
	} else {
		print ("ERROR: HTTP Sync Call failed");
	}
	r2p.cmd("pi 5 @ entry0", closure:{
		(str:String)->() in
		print ("Disasm:\n\(str)");
	});
}
```

But Swift also supports the R2Pipe Env interface:

```swift
if let r2p = R2Pipe("#!pipe") {
	r2p.cmd ("?V", closure:{
		(str:String) in
		print ("R2PIPE.SWIFT: \(str)");
		exit (0);
	});
	NSRunLoop.currentRunLoop().run();
} else {
	print ("Invalid R2PIPE_{IN|OUT} environment")
}
```

Which can be executed from inside r2:

```
$ r2 -qc '#!pipe ./main' -
Hello r2pipe.swift!
R2PIPE.SWIFT: 0.10.0-git aka 0.9.9-790-gccd2e51 commit 8899
```

Compilation
-----------
Use `make` with the following options:

* HAVE_SPAWN=1         # or 0
* USE_NSURL_SESSION=0  # or 1 - required for iOS9
* TARGET=ios           # select ios as target
* IOS=8.4              # specify iOS SDK version

TODO
----
* Add support for `#!pipe`
* Better support for JSON

JSON Support
------------
Use or integrate one of the following libraries:

* https://github.com/SwiftyJSON/SwiftyJSON
* https://github.com/dankogai/swift-json/
