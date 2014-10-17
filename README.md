r2pipe
======

![r2pipe logo](http://lolcathost.org/b/r2pipe.png)

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

Target languages for this API are the following:

  * NodeJS
  * Go
  * C# / .NET
  * Python
  * Ruby
  * Java
  * Perl


--pancake
