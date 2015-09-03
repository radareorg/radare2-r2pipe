R2PIPE.SWIFT
============

Swift 2.0 API to communicate with a radare2 session using r2pipe.

Author: pancake <pancake@nopcode.org>

Description
-----------
This API provides support to run commands in r2 using different channels:

* http
* spawn

And can be accessed:

* sync
* async

And optionally supports to parse JSON

Example
-------
```swift
if let r2p = R2Pipe(url:"http://cloud.radare.org/cmd/") {
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
