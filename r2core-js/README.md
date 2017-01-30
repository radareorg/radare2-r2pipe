r2core.js
=========

This is the NodeJS module and Browser ready emscripten builds of radare2.

```js
const r2core = require('r2core');
const c = new r2core();
console.log(c.cmd('?E Hello World'));
```

```
$ node
> console.log(new require('r2core')().cmd('?E Hello World'))
 .--.     .-------------.
 | _|     |             |
 | O O   <  Hello World |
 |  |  |  |             |
 || | /   `-------------'
 |`-'|
 `---'
```

You can create multiple instances of RCore and you can open external resources too:

```js
c.open('/bin/ls');
```

The API provided is similar to the r2pipe one, so you can reuse the same scripts.

* .open() - opens a file from an external resource (vfs/net)
* .cmd() - run a command in r2 and return the string
* .cmdj() - same as above but parsing the output as JSON
* .free() - destroy the instance

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
