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

Use `async with` or `await r2.close()` / `await r2.quit()` to clean up. Closing
keeps the caller's event loop open. Commands on one client run in sequence,
including commands submitted with `asyncio.gather`. Canceling a command that
has already started lets its response finish draining before the next command
runs; the command may still change radare2 state. Closing waits for these
started commands and rejects commands still waiting to run. Callbacks receive
the raw response before JSON parsing, as with blocking calls.
