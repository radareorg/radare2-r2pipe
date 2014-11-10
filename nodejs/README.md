Pipe bindings for radare2 (r2pipe)
==================================
![r2pipe logo](http://lolcathost.org/b/r2pipe.png)

The r2pipe APIs are based on a single r2 primitive found behind r_core_cmd_str() which is a function that accepts a string parameter describing the r2 command to run and returns a string with the result.

The decision behind this design comes from a series of benchmarks with different libffi implementations and resulted that using the native API is more complex and slower than just using raw command strings and parsing the output.

As long as the output can be tricky to parse, it's recommended to use the JSON output and deserializing them into native language objects which results much more handy than handling and maintaining internal data structures and pointers.

Also, memory management results into a much simpler thing because you only have to care about freeing the resulting string.


Getting Started
===============

This plugin requires radare >= `0.9.8`

Once radare2 is installed, you may install this plugin using this command:

```shell
npm install r2pipe
```

Once the plugin has been installed, you can load it with this line of JavaScript:

```js
var r2pipe = require('r2pipe');
```

Access methods
==============

There are multiple ways to interact with a radare2 session

### pipe

Spawns a new process and comunicate with it through standard stdin, stdout, stderr file descriptors

```js
var r2pipe = require('r2pipe');

function doSomeStuff(r2) {
   ...
}

r2pipe.pipe ("/bin/ls", doSomeStuff);
```

### launch

Launch radare2 and listen for cmds through a tcp port

```js
var r2pipe = require('r2pipe');

function doSomeStuff(r2) {
   ...
}

r2pipe.launch ("/bin/ls", doSomeStuff);
```


### connect

Connect to an already running radare2 instance running an http listener

```bash
~$ r2 -
 -- Trust no one, nor a zero. Both lie.
[0x00000000]> =h 8182
Starting http server...
open http://localhost:8182/
r2 -C http://localhost:8182/cmd/
```

```js
var r2pipe = require('r2pipe');

function doSomeStuff(r2) {
   ...
}

r2pipe.connect ("http://localhost:8182/cmd/", doSomeStuff);
```

API
===

r2pipes provides three basic commands


### cmd

Runs a radare2 command

```js
var r2pipe = require('r2pipe');

function doSomeStuff(r2) {
   r2.cmd ("iS", function(output) {
    console.log (output);
  });
}

r2pipe.launch ("/bin/ls", doSomeStuff);
```


### cmdj

Runs a radare2 command and try to convert the output into an object.

Note that this will only work with commands producing JSON output.

```js
var r2pipe = require('r2pipe');

function doSomeStuff(r2) {
   r2.cmdj ("iSj", function(output) {
    if (output !== null)
       console.log (output);
    else
       console.log("An error has occurred");
  });
}

r2pipe.launch ("/bin/ls", doSomeStuff);
```

In case of error "null" will be passed as argument to the callback instead of an valid object

### quit

Close the connection or kill the radare spawned process

```js
var r2pipe = require('r2pipe');

function doSomeStuff(r2) {
   r2.quit();
}

r2pipe.launch ("/bin/ls", doSomeStuff);
```


Example
=======

```js
var r2pipe = require ("./");


function doSomeStuff(r2) {

  r2.cmdj ("aij entry0+2", function(o) {
    console.log (o);
  });

  r2.cmd ('af @ entry0', function(o) {
    r2.cmd ("pdf @ entry0", function(o) {
      console.log (o);
      r2.quit ()
    });
  });

}


r2pipe.pipe ("/bin/ls", doSomeStuff);
r2pipe.launch ("/bin/ls", doSomeStuff);
r2pipe.connect ("http://cloud.rada.re/cmd/", doSomeStuff);
```

