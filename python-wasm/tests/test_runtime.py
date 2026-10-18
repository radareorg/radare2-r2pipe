"""Exercise the actual Wasmer engine, not a mocked memory/exports interface."""
from importlib import import_module
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import r2pipe_wasm

try:
    from wasmer import wat2wasm
    import_module("wasmer_compiler_cranelift")
    HAVE_WASMER = True
except ImportError:
    HAVE_WASMER = False

FIXTURE = Path(__file__).resolve().parents[2] / "typescript/tests/fixtures/wasm-api.wasm"


@unittest.skipUnless(HAVE_WASMER, "Wasmer native SDK not installed")
class RuntimeTest(unittest.TestCase):
    def test_commands_growth_json_and_cleanup(self):
        r2 = r2pipe_wasm.open(wasm=FIXTURE)
        exports = r2._exports
        try:
            self.assertEqual(r2.cmd("hello ☃"), "hello ☃")
            self.assertEqual(r2.cmd("grow memory"), "grow memory")
            long_output = "g" + "hé" * 4000
            self.assertEqual(r2.cmd(long_output), long_output)
            self.assertEqual(r2.cmdj("json"), {"offset": 18446744073709551615})
            with self.assertRaises(ValueError):
                r2.cmd("embedded\0NUL")
            with self.assertRaisesRegex(RuntimeError, "null string"):
                r2.cmd("!error")
            with self.assertRaises(ValueError):
                r2.cmdj("invalid JSON")
            self.assertEqual(exports.allocated_strings(), exports.freed_strings())
        finally:
            r2.quit()
        r2.quit()
        self.assertEqual(exports.freed_cores(), 1)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            r2.cmd("closed")

    def test_open_failure_frees_core(self):
        # Observe the instance created by the real runtime during failed construction.
        from unittest.mock import patch
        from wasmer import Instance
        instances = []
        def instantiate(*args):
            instance = Instance(*args)
            instances.append(instance)
            return instance
        with patch("wasmer.Instance", side_effect=instantiate):
            with self.assertRaises(OSError):
                r2pipe_wasm.open("!missing", wasm=FIXTURE)
        exports = instances[0].exports
        self.assertEqual(exports.freed_cores(), 1)
        self.assertEqual(exports.allocated_strings(), exports.freed_strings())

    def test_bad_module_and_host_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            wasm = Path(temporary) / "bad.wasm"
            wasm.write_bytes(wat2wasm('(module)'))
            with self.assertRaisesRegex(ValueError, "Missing WASM exports"):
                r2pipe_wasm.open(wasm=wasm)
            wasm.write_bytes(wat2wasm('(module (import "r2" "system" (func)))'))
            with self.assertRaisesRegex(ValueError, "Unsupported WASM import"):
                r2pipe_wasm.open(wasm=wasm)

    def test_socket_import_is_denied(self):
        # Add WASI socket import to a small reactor. The callback must return ENOTSUP.
        wat = '''(module
          (import "wasi_snapshot_preview1" "sock_accept" (func $sock (param i32 i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "malloc") (param i32) (result i32) i32.const 1024)
          (func (export "free") (param i32))
          (func (export "r_core_new") (result i32) i32.const 1)
          (func (export "r_core_free") (param i32))
          (func (export "r_core_cmd_str") (param i32 i32) (result i32) i32.const 2048)
          (func (export "r_core_file_open") (param i32 i32 i32 i64) (result i32) i32.const 1)
          (func (export "r_core_bin_load") (param i32 i32 i64) (result i32) i32.const 1)
          (func (export "probe") (result i32) i32.const 0 i32.const 0 i32.const 0 call $sock))'''
        with tempfile.TemporaryDirectory() as temporary:
            wasm = Path(temporary) / "sockets.wasm"
            wasm.write_bytes(wat2wasm(wat))
            with r2pipe_wasm.open(wasm=wasm) as r2:
                self.assertEqual(r2._exports.probe(), 58)


@unittest.skipUnless(HAVE_WASMER and os.environ.get("R2PIPE_WASM"), "Set R2PIPE_WASM for real radare2")
class Radare2Test(unittest.TestCase):
    def test_shared_files_and_isolation(self):
        with tempfile.TemporaryDirectory() as temporary:
            shared = Path(temporary)
            sample = shared / "sample.bin"
            sample.write_bytes(bytes.fromhex("9090c3"))
            wasm = os.environ["R2PIPE_WASM"]
            with r2pipe_wasm.open("/work/sample.bin", wasm=wasm,
                                 preopens={"/work": shared}) as r2:
                self.assertEqual(r2.cmdj("pxj 3"), [144, 144, 195])
                r2.cmd("e asm.arch=x86; e asm.bits=64")
                self.assertIn("nop", r2.cmd("pd 3"))
                r2.cmd("px 3 > /work/hexdump.txt")
                self.assertIn("9090", (shared / "hexdump.txt").read_text())
                r2.cmd("!touch /work/spawned")
                self.assertFalse((shared / "spawned").exists())
            with self.assertRaises(OSError):
                r2pipe_wasm.open(str(sample), wasm=wasm)


if __name__ == "__main__":
    unittest.main()
