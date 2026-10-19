# r2pipe for Python

Interact with radare2 using the #!pipe command or in standalone scripts
that communicate with local or remote r2 via pipe, tcp or http.

## Installation

```
$ pip install r2pipe
```

or

```
$ pip3 install r2pipe
```

## Usage example:

```python
import r2pipe

r2 = r2pipe.open("/bin/ls")
r2.cmd('aa')
print(r2.cmd("afl"))
print(r2.cmdj("aflj"))            # evaluates JSONs and returns an object
print(r2.cmdj("ij")["core"]["format"])  # shows file format
r2.quit()
```

## Structured commands (r2pipe2)

`cmd2()` accepts boolean `trim` and `json` options. `trim=True` strips output
whitespace; `json=True` asks radare2 to embed the command's JSON output in
the response's `res` field. `cmd2j()` defaults both options to `True`, and
explicit `False` values override those defaults.

```python
with r2pipe.open("-", flags=["-N"]) as r2:
    print(r2.cmd2("?e hello", trim=True).res)  # "hello"
    print(r2.cmd2("ij", json=True).res.core.file)
    print(r2.cmd2j("?e hello", json=False, trim=False).res)  # "hello\n"
```

Both methods accept `callback=...`, which receives the raw response string
before Python parses the JSON. Callbacks are handled in Python and are never
included in the request JSON. Synchronous `call()`, `cmd()`, `cmdj()`, and
`cmdJ()` also support callbacks. Unknown r2pipe2 keywords, non-boolean flags,
and callbacks that are neither callable nor `None` raise `TypeError` before
execution. `call()` accepts only the optional `callback` keyword.

## Asyncio

Import the async client to await commands inside an event loop:

```python
import asyncio
from r2pipe.open_async import open as async_open

async def main():
    async with async_open("/bin/ls", flags=["-N"]) as r2:
        reply = await r2.cmd2j("ij")
        print(reply.res.core.file)
        print(await r2.cmd("afl"))

asyncio.run(main())
```

`cmd`, `cmdj`, `cmdJ`, `call`, `cmd2`, and `cmd2j` return awaitables inside
the client's event loop. Outside a running loop, the async client keeps its
existing blocking behavior. A client created before starting the event loop
can be used inside it; once commands have run, use that same loop for the
rest of the session. Embedded `#!pipe` and `r2lang` commands retain their
blocking behavior.

Native `ccall://` sessions also support these awaitable methods. Each session
runs core creation, commands, and cleanup on one dedicated worker thread so
native calls leave the event loop responsive.

Use `async with` or `await r2.close()` / `await r2.quit()` to clean up. Closing
keeps the caller's event loop open. Commands on one client run in sequence,
including commands submitted with `asyncio.gather`. Canceling a command that
has already started lets its response finish draining before the next command
runs; the command may still change radare2 state. Closing waits for these
started commands and rejects commands still waiting to run. Callbacks receive
the raw response before JSON parsing, as with blocking calls.

Async HTTP/TCP connection failures, read errors, and response timeouts raise
exceptions from the command call (or its awaitable). Success callbacks are
not called for failed commands; errors are not returned as response strings.

### IO address values

IO request addresses may be hexadecimal strings or legacy JSON integers.
`r2pipe.parse_address(value)` validates and returns an exact unsigned 64-bit
Python `int`. It rejects booleans, floats, invalid strings and out-of-range
values; `cmdj()` otherwise preserves the usual JSON types.

```python
r2pipe.parse_address("0xffffffffffffffff")  # 18446744073709551615
r2pipe.parse_address(9007199254740993)       # exact legacy integer
```

See `examples/io-plugin.py` for a complete memory-backed IO server accepting
both representations.

## Releasing

Update the version in `pyproject.toml`, then run:

```sh
make check  # build the source archive and wheel, then validate their metadata
make pub    # build, validate, and upload to PyPI
```

The first build creates `.venv-release` and installs the build and upload tools
there. This requires Python 3.9 or newer with `venv` support and access to PyPI.
Use `make PYTHON3=python3.12` to choose the interpreter when creating the environment.
Run `make twine` to update the release tools. `BUILD` and `TWINE` remain overridable.

For uploads, provide a PyPI API token through Twine's password prompt,
`TWINE_PASSWORD`, or the `[pypi]` section in `~/.pypirc`:

```ini
[pypi]
username = __token__
password = <your PyPI API token>
```
