r2pipe
======

![r2pipe logo](https://raw.githubusercontent.com/radare/radare2-r2pipe/master/r2pipe.png)

The r2pipe APIs are based on a single r2 primitive found behind `r_core_cmd_str()`
which is a function that accepts a string parameter describing the r2 command to
run and returns a string with the result.

The decision behind this design comes from a series of benchmarks with different
libffi implementations and resulted that using the native API is more complex and
slower than just using raw command strings and parsing the output.

As long as the output can be tricky to parse, it's recommended to use the JSON
output and deserializing them into native language objects which results much more
handy than handling and maintaining internal data structures and pointers.

Also, memory management results into a much simpler thing because you only have
to care about freeing the resulting string.

This directory contains different implementations of the r2pipe API for different
languages which could handle different communication backends:

  * Fork r2 -q0 and communicate with pipe(2)
  * Plain TCP connection
  * HTTP queries (connecting to a remote webserver)
  * RAP protocol (r2 own's remote protocol)

Most of the language enable asyncronous capabilities in order to handle the result
of the operation in a callback, allowing a single program to interact with multiple
instances or connections to different r2 sessions at the same time.

  * Syncronous
  * Asyncronous

In addition, r2pipe scripts can be used to write plugins for radare2 or extend current functionalities:

  * Assembler/Disassembler plugin for RAsm
  * RIO plugin to abstract read/write/system operations
  * Syscall handler for the ESIL emulator
  * ...

The most supported languages are:

  * NodeJS
  * Python

But there is r2pipe for:

	          pipe spawn async http tcp rap json plug
	C           x     x     -    x    x   x    x    x
	C++/Qt      x     x     -    -    -   -    x    -
	D           x     -     -    -    -   -    x    -
	NodeJS      x     x     x    x    x   -    x    x
	Python      x     x     x    x    x   x    x    x
	Perl        x     x     -    x    x   -    x    -
	Nim         -     -     -    x    -   -    -    -
	Swift       x     x     x    x    -   -    x    -
	C# / F#     x     x     x    x    -   -    -    -
	Haskell     x     x     -    x    -   -    x    -
	Java/Groovy -     x     -    x    -   -    -    -
	Go          x     x     -    -    -   -    x    -
	Ruby        x     x     -    -    -   -    x    -
	Rust        x     x     -    -    -   -    x    -
	Vala        -     x     x    -    -   -    -    -
	Erlang      x     x     -    -    -   -    -    -
	Lisp        -     x     -    -    -   -    x    -
	NewLisp     x     -     -    -    -   -    -    -
	Dlang       x     -     -    -    -   -    x    -
	Ocaml       -     x     -    -    -   -    x    -

--pancake
