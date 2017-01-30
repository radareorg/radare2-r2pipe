r2core.js
=========

This is the NodeJS module and Browser ready emscripten builds of radare2.

	$ npm install r2core

And now you can run things like that:

	$ node -e "console.log(new require('r2core')().cmd('?E Hello World'))"
	 .--.     .-------------.
	 | _|     |             |
	 | O O   <  Hello World |
	 |  |  |  |             |
	 || | /   `-------------'
	 |`-'|
	 `---'

API
---
The API provided is similar to the r2pipe one, so you can reuse the same scripts.

* .open() - opens a file from an external resource (vfs/net)
* .cmd() - run a command in r2 and return the string
* .cmdj() - same as above but parsing the output as JSON
* .free() - destroy the instance

Example
-------

You can create multiple instances of RCore and you can open external resources too:

```js
const R2Core = require('r2core');
const c = new R2Core();
const c2 = new R2Core();
console.log(c.cmd('wv 123'));
console.log(c2.cmd('p8 4'));
```

Testing
-------

To get the latest version of r2core.js download it from npm or [http://cloud.rada.re/asmjs/r2core.js](http://cloud.rada.re/asmjs/r2core.js).

Building
--------

If you are not satisfied by downloading precompiled programs you can also build it yourself by using the `radare2-release` tool that is available via `r2pm`:
 
```sh
$ r2pm -r r2rls docker_asmjs
```

Now you may run `make` to minify the radare2.js and generating r2core.js.
This process is using uglifyjs and closurejs and requires at least 2GB of RAM.

You can now use this file from nodejs or the browser

* open webtest.html
* node test.js

Future
------

* Integration with brotli (Compression goes from 16MB to 1.8MB)
* Open Buffers instead of fs/network resources

Author
------

* pancake <pancake@nopcode.org>
