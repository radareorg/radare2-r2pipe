r2core.js
=========

This is the NodeJS module and Browser ready emscripten builds of radare2.

	const r2core = require('r2core');
	const c = new r2core();
	console.log(c.cmd('?E Hello World'));

You can create multiple instances of RCore and you can open external resources too:

	c.open('/bin/ls');

Building
--------

Build radare2.js with radare2-release

	r2pm -r r2rls docker_asmjs

Now you may run `make` to minify the radare2.js and generating r2core.js.
This process is using uglifyjs and closurejs

or get it from:

	http://cloud.rada.re/asmjs/radare2.tiny.js

You can now use this file from nodejs or the browser

	open webtest.html

	node test.js

Future
------

* Integration with brotli (Compression goes from 16MB to 1.8MB)
* Open Buffers instead of fs/network resources

Author
------

* pancake <pancake@nopcode.org>
