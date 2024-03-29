# r2pipe API for radare2

![r2pipe logo](http://lolcathost.org/b/r2pipe.png)

This is a reimplementation in TypeScript of the original `r2pipe` and `r2pipe-promise` modules for NodeJS.

## Usage

If you are using r2skel (`r2pm -ci r2skel`) you can get a hello world to use this module with the following line:

```
r2pm -r r2skel r2-script-r2pipe-ts hello-ts
make -C hello-ts
```

## Basics

The basic fundamentals of r2pipe is that you the API provides the most basic communication channel with r2, this is a single function called `cmd` that takes the command to be executed and returns the output of the command as a string.

As long as many commands in r2 return JSON, it is ideal for working with TS/JS, because using `cmdj()` the API will convert the output into an object.

In order to provide compatibility with all kind of backends, the whole api has been made asynchronous, this allows the developer to change the backend by only changing one line.

Note that stderr events are not handled by this API, process stdin/stdout is also not handled by r2pipe, but there are ways to manage it if needed.

## Supported r2pipe methods

* http (since node 18, plaintext http networking is not allowed unless you use the `--insecure-http-parser` flag)
* spawn (launch a new radare2 process and communicate with it sending async commands to collect the response)
* local (the local pipe is used when launching scripts from `r2 -i too.ts` or `> . too.ts`

## r2Frida-Compile

radare2 also supports the esm modules generated by frida-compile. But it is worth to mention that r2frida comes with a C reimplementation of frida-compile (python). Which ships a typescript compiler and is able to pack multiple ts/js files into a single file.

## Runtime

This module is suposed to run with NodeJS, under some circunstancies, it may also with with r2js, bun or deno.

## Author

--pancake <@nopcode.org>
