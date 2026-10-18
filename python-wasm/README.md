# r2pipe-wasm (Python + Wasmer)

Run radare2 inside Python as a WebAssembly instance, without a native radare2
installation or a subprocess. This is a separate package (`r2pipe_wasm`) with
an r2pipe-like `open`, `cmd`, `cmdj`, `quit` and context-manager interface.

The backend uses Wasmer's Python SDK and the `wasi-api` reactor build, calling
`r_core_new`, `r_core_cmd_str`, `r_core_file_open`, `r_core_bin_load` and
`r_core_free` directly. Command strings and results are allocated/freed in guest
memory. Each connection owns its own instance and core.

## Install

From this repository:

```sh
python3.9 -m venv .venv
. .venv/bin/activate
pip install ./python-wasm
```

**Runtime compatibility:** Wasmer's published Python SDK is 1.1.0 and its native
wheels have limited Python/platform coverage. CPython 3.9 on Linux x86_64 is
verified here. A newer Python may install a placeholder package that raises
`ImportError`; installing successfully alone does not prove runtime support.
Use a supported native wheel or build the Wasmer Python SDK and matching
Cranelift extension yourself. This package does not fall back to a CLI/runtime
subprocess. Release discovery/downloading uses only the Python standard library
and can be imported without loading Wasmer.

## Analyze a file

```python
from pathlib import Path
import r2pipe_wasm as r2pipe

# Only this directory is shared. The filename is a path in the guest environment.
samples = Path("samples").resolve()
with r2pipe.open("/samples/program", version="6.1.4",
                 preopens={"/samples": samples}) as r2:
    print(r2.cmdj("ij"))
    r2.cmd("aaa")
    print(r2.cmdj("aflj"))
    print(r2.cmd("pd 10"))
```

By default `open()` downloads/caches the **newest stable release with a
`wasi-api` asset**. A newer release without that asset is skipped (for example,
6.2.4 has no API asset, while 6.2.2 does). CLI `wasi` and `wasi-browser` builds
are not substitutes. Compilation takes place when opening each connection;
keep the connection open for multiple commands.

**Known upstream release issue:** the published 6.2.2 API module traps inside
`r_core_new()` (`ht_pp_find_kv` during config initialization), reproduced with
both Wasmer and Node WASI. The examples pin **6.1.4**, verified end to end.
The default still selects the newest stable API asset and propagates guest
errors; it does not silently fall back to an older version. Use `version=` or
`wasm=` to select a working release/build.

## List releases, choose a version, download once

```python
from r2pipe_wasm import DownloadManager, api_asset, open

manager = DownloadManager(cache_dir=".cache/radare2")
for release in manager.releases():  # paginates the GitHub releases API
    asset = api_asset(release)
    print(release["tag_name"], asset["name"] if asset else "no API build")

print(manager.select()["tag_name"])       # newest stable API release
wasm = manager.download("6.1.4")           # exact tag, or "latest" (default)
with open(wasm=wasm) as r2:                # local module: no network requests
    print(r2.cmd("?V"))

# Or select a release directly when opening:
with open(version="6.1.4", manager=manager) as r2:
    print(r2.cmd("?V"))
```

`releases()` includes prereleases and releases without WASM assets; `select()`
and `download()` reject explicit tags without an API build. Explicit prerelease
tags are allowed. GitHub HTTP errors (including rate limits) propagate to the
caller. An optional `token=` is sent only to the GitHub API, never to the guest
or release download URL. No host environment variables are inherited by WASI.

The default cache is `$XDG_CACHE_HOME/r2pipe-wasm` or `~/.cache/r2pipe-wasm`.
Downloads use temporary files and an atomic replacement, validate the WASM
header, and verify GitHub's SHA-256 asset digest when provided. Archive members
are never extracted by their paths. `download(force=True)` refreshes a cached
module. Version selection still contacts GitHub on a cache hit; pass `wasm=`
for fully offline operation.

## Share files and save results

`preopens` maps **guest absolute directory → host directory**. There are no
preopened host directories by default, and opening a host path does not share it
automatically. Mappings expose the directory's contents with read/write access
subject to host permissions; use a dedicated directory or copies for inputs.
The initial binary is opened read-only, but commands can write shared files.

```python
from pathlib import Path
import r2pipe_wasm

shared = Path("work").resolve()
shared.mkdir(exist_ok=True)
(shared / "sample.bin").write_bytes(bytes.fromhex("9090c3"))

with r2pipe_wasm.open("/work/sample.bin", wasm="radare2.wasm",
                     preopens={"/work": shared}) as r2:
    r2.cmd("e asm.arch=x86; e asm.bits=64")
    print(r2.cmd("pd 3"))
    r2.cmd("px 3 > /work/hexdump.txt")

print((shared / "hexdump.txt").read_text())
```

The WASM guest has **no network or system-program execution capability**:
only WASI Preview1 imports are accepted, all socket calls return `ENOTSUP`, and
no HTTP/browser callbacks or WASIX/process-spawning imports are supplied.
Commands such as `!sh`, native debugging and network IO cannot use host services.
The host-side download manager uses HTTPS independently of the guest.
WASI stdout/stderr remain available; this is a synchronous analysis API, not an
interactive terminal. Use `quit()`/`close()` or a context manager to release it.
`cmdj()` raises `JSONDecodeError` for invalid JSON; commands after closing fail.

## Tests

```sh
python -m unittest discover -s python-wasm/tests -v
# Also run the real WASI module, file sharing and isolation checks:
R2PIPE_WASM=/absolute/path/to/radare2.wasm \
    python -m unittest discover -s python-wasm/tests -v
```

The offline runtime tests reuse the repository's small TypeScript WASM API
fixture. Downloader tests do not require Wasmer or network access.
