"""An r2pipe-like interface to a radare2 WASI reactor running inside Wasmer."""

import json
from pathlib import Path
import threading

from .releases import DownloadManager, api_asset

__all__ = ["open", "R2Pipe", "DownloadManager", "api_asset"]


class R2Pipe:
    """One isolated WASM instance/core; only explicit preopens share host files."""

    def __init__(self, filename=None, *, wasm=None, version="latest", preopens=None,
                 manager=None, network=False):
        # Keep release management usable without the native Wasmer extension.
        try:
            from wasmer import engine, wasi, Function, ImportObject, Instance, Module, Store
            from wasmer_compiler_cranelift import Compiler
        except ImportError as error:
            raise ImportError(
                "Wasmer 1.1 and its Cranelift compiler need a supported native wheel; "
                "see python-wasm/README.md (CPython 3.9 on Linux x86_64)."
            ) from error
        self._lock = threading.RLock()
        self._core = 0
        self._instance = None
        self._exports = None
        self._wasi = None
        self._http = None
        path = Path(wasm) if wasm is not None else (manager or DownloadManager()).download(version, network=network)
        store = Store(engine.Universal(Compiler))
        module = Module(store, path.read_bytes())
        from .http import HttpBridge
        if network:
            self._http = HttpBridge(self)
        # Only the existing HTTP ABI is allowed in addition to Preview1.
        for imported in module.imports:
            if imported.module == "r2" and imported.name in ("http_get", "http_post"):
                continue
            if imported.module != "wasi_snapshot_preview1":
                raise ValueError(f"Unsupported WASM import {imported.module}.{imported.name}; "
                                 "use a wasi-api build")
        if network and not any(item.module == "r2" and item.name == "http_get" for item in module.imports):
            raise ValueError("This WASM build has no HTTP bridge; use a wasi-api-http build")
        required = {"memory", "malloc", "free", "r_core_new", "r_core_free",
                    "r_core_cmd_str", "r_core_file_open", "r_core_bin_load"}
        missing = required - {export.name for export in module.exports}
        if missing:
            raise ValueError(f"Missing WASM exports {', '.join(sorted(missing))}; "
                             "use a wasi-api build")
        state = wasi.StateBuilder("radare2")
        for guest, host in (preopens or {}).items():
            if not guest.startswith("/") or ".." in guest.split("/") or "\0" in guest:
                raise ValueError("Preopen guest paths must be absolute, without '..' or NUL")
            host = Path(host).resolve(strict=True)
            if not host.is_dir():
                raise ValueError(f"Preopen is not a directory: {host}")
            state.map_directory(guest, str(host))
        self._wasi = state.finalize()
        imports = ImportObject()
        if module.imports:
            functions = self._wasi.generate_imports(store, wasi.Version.SNAPSHOT1)[
                "wasi_snapshot_preview1"]
            for imported in module.imports:
                if imported.name.startswith("sock_"):
                    # Preview1 ENOTSUP. Also covers sock_accept, absent in Wasmer 1.1.
                    functions[imported.name] = Function(store, lambda *_args: 58, imported.type)
            imports.register("wasi_snapshot_preview1", functions)
            imports.register("r2", {
                item.name: Function(store, getattr(self._http, item.name) if network
                                    else lambda *_args: 0, item.type)
                for item in module.imports if item.module == "r2"
            })
        self._instance = Instance(module, imports)
        self._exports = self._instance.exports
        try:
            if "_initialize" in {export.name for export in module.exports}:
                self._exports._initialize()
            self._core = self._exports.r_core_new()
            if not self._core:
                raise MemoryError("Cannot allocate a radare2 core")
            self.cmd("e scr.color=0")
            self.cmd("e scr.interactive=false")
            if filename is not None:
                pointer = self._allocate(str(filename))
                try:
                    if not self._exports.r_core_file_open(self._core, pointer, 4, 0):
                        raise OSError(f"Cannot open {filename!r} in WASM; "
                                      "host files require an explicit preopens mapping")
                    # Signed i64 -1 is UT64_MAX: use the binary's preferred base address.
                    self._exports.r_core_bin_load(self._core, pointer, -1)
                finally:
                    self._exports.free(pointer)
        except BaseException:
            self.quit()
            raise

    def _allocate(self, text):
        if "\0" in text:
            raise ValueError("WASM strings cannot contain NUL characters")
        data = text.encode("utf-8") + b"\0"
        pointer = self._exports.malloc(len(data)) & 0xffffffff
        if not pointer:
            raise MemoryError("Cannot allocate a WASM string")
        try:
            # Acquire a fresh buffer after calls which may grow linear memory.
            with memoryview(self._exports.memory.buffer) as memory:
                memory[pointer:pointer + len(data)] = data
        except BaseException:
            self._exports.free(pointer)
            raise
        return pointer

    def _read_string(self, pointer):
        chunks = []
        with memoryview(self._exports.memory.buffer) as memory:
            # Scan in chunks instead of copying the entire guest heap per command.
            while pointer < len(memory):
                chunk = bytes(memory[pointer:pointer + 4096])
                end = chunk.find(b"\0")
                if end >= 0:
                    chunks.append(chunk[:end])
                    return b"".join(chunks).decode("utf-8", errors="replace")
                chunks.append(chunk)
                pointer += len(chunk)
        raise RuntimeError("Unterminated WASM command output")

    def cmd(self, command):
        """Execute a command and return its output; calls are serialized per instance."""
        with self._lock:
            if not self._core:
                raise RuntimeError("r2pipe WASM instance is closed")
            source = self._allocate(command)
            output = 0
            try:
                output = self._exports.r_core_cmd_str(self._core, source) & 0xffffffff
                if not output:
                    raise RuntimeError("radare2 WASM command returned a null string")
                return self._read_string(output)
            finally:
                if output:
                    self._exports.free(output)
                self._exports.free(source)

    def cmdj(self, command):
        """Execute a JSON command; malformed JSON raises JSONDecodeError."""
        return json.loads(self.cmd(command))

    def quit(self):
        """Free the core and release the instance; safe to call more than once."""
        with self._lock:
            try:
                if self._core:
                    self._exports.r_core_free(self._core)
            finally:
                self._http = None
                self._core = 0
                self._exports = None
                self._instance = None
                self._wasi = None

    close = quit

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.quit()


def open(filename=None, **kwargs):
    """Open a guest filename (or an empty core), downloading the latest API by default."""
    return R2Pipe(filename, **kwargs)
