"""HTTP callbacks and real C HTTP APIs, using a local server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import r2pipe_wasm
try:
    from wasmer import wat2wasm
    HAVE_WASMER = True
except ImportError:
    HAVE_WASMER = False


class HttpServerTest(unittest.TestCase):
    def setUp(self):
        self.requests = []
        requests = self.requests
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.command, self.path, dict(self.headers)))
                self.send_response(404 if self.path == '/missing' else 200)
                self.end_headers()
                self.wfile.write(b'\x90\x00\xc3')
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                requests.append((self.command, self.path, dict(self.headers), body))
                self.send_response(201)
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_args):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f'http://127.0.0.1:{self.server.server_port}/sample'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def call(self, r2, method, url=None, headers=True):
        e = r2._exports
        pointers = []
        def alloc(text):
            pointer = r2._allocate(text)
            pointers.append(pointer)
            return pointer
        address = alloc(url or self.url)
        # Direct C functions accept a NULL-terminated char**; imports use joined lines.
        fields = alloc('Authorization: Bearer test\nContent-Type: application/json')
        is_real = isinstance(self, RealHttpTest)
        if headers and is_real:
            first, second = alloc('Authorization: Bearer test'), alloc('Content-Type: application/json')
            fields = alloc(' ' * 12)
            with memoryview(e.memory.buffer) as memory:
                struct.pack_into('<III', memory, fields, first, second, 0)
        status, length = alloc('    '), alloc('    ')
        result = 0
        try:
            fn = getattr(e, 'r_socket_http_' + method) if is_real else e.http_request
            args = [address, fields if headers else 0]
            if not is_real:
                args.insert(0, int(method == 'post'))
            if method == 'post':
                args.append(alloc('{"prompt":"hello món"}'))
            elif not is_real:
                args.append(0)
            result = fn(*args, status, length) & 0xffffffff
            if not result:
                return None
            with memoryview(e.memory.buffer) as memory:
                code = struct.unpack_from('<i', memory, status)[0]
                size = struct.unpack_from('<i', memory, length)[0]
                body = bytes(memory[result:result + size])
                self.assertEqual(memory[result + size], 0)
            return code, body
        finally:
            if result:
                e.free(result)
            for p in pointers:
                e.free(p)


@unittest.skipUnless(HAVE_WASMER, 'Wasmer native SDK not installed')
class HttpImportsTest(HttpServerTest):
    def test_imports_opt_in_get_post_status_and_binary(self):
        wat = '''(module
          (import "r2" "http_request" (func $request (param i32 i32 i32 i32 i32 i32) (result i32)))
          (export "http_request" (func $request))
          (memory (export "memory") 1)
          (global $heap (mut i32) (i32.const 4096))
          (func (export "malloc") (param $n i32) (result i32)
            global.get $heap global.get $heap local.get $n i32.add global.set $heap)
          (func (export "free") (param i32))
          (func (export "r_core_new") (result i32) i32.const 1)
          (func (export "r_core_free") (param i32))
          (func (export "r_core_cmd_str") (param i32 i32) (result i32) i32.const 2048)
          (func (export "r_core_file_open") (param i32 i32 i32 i64) (result i32) i32.const 1)
          (func (export "r_core_bin_load") (param i32 i32 i64) (result i32) i32.const 1))'''
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'http.wasm'
            path.write_bytes(wat2wasm(wat))
            with r2pipe_wasm.open(wasm=path) as r2:
                self.assertIsNone(self.call(r2, 'get'))
                self.assertIsNone(self.call(r2, 'post'))
                self.assertEqual(self.requests, [])
            with r2pipe_wasm.open(wasm=path, network=True) as r2:
                self.assertEqual(self.call(r2, 'get'), (200, b'\x90\x00\xc3'))
                self.assertEqual(self.call(r2, 'post'), (201, '{"prompt":"hello món"}'.encode()))
                self.assertEqual(self.requests[-1][2]['Authorization'], 'Bearer test')
                self.assertEqual(self.requests[-1][2]['Content-Type'], 'application/json')
                self.assertEqual(self.call(r2, 'get', self.url.replace('/sample', '/missing'))[0], 404)
                self.assertIsNone(self.call(r2, 'get', 'file:///etc/passwd'))


@unittest.skipUnless(os.environ.get('R2PIPE_WASM_NETWORK'), 'Set R2PIPE_WASM_NETWORK to a wasi-api-http build')
class RealHttpTest(HttpServerTest):
    def test_c_http_apis_and_sandbox(self):
        wasm = os.environ['R2PIPE_WASM_NETWORK']
        with r2pipe_wasm.open(wasm=wasm) as r2:
            self.assertIsNone(self.call(r2, 'get'))
            self.assertIsNone(self.call(r2, 'post'))
            self.assertEqual(self.requests, [])
        with r2pipe_wasm.open(wasm=wasm, network=True) as r2:
            self.assertEqual(self.call(r2, 'get'), (200, b'\x90\x00\xc3'))
            self.assertEqual(self.call(r2, 'post'), (201, '{"prompt":"hello món"}'.encode()))
            self.assertEqual(self.requests[-1][2]['Authorization'], 'Bearer test')
            self.assertEqual(self.call(r2, 'get', headers=False), (200, b'\x90\x00\xc3'))
            # Embedded JS uses the exact same C path, without a shell.
            script = 'const response = r2.http("POST", %s, "Content-Type: application/json", "hello món");' % json.dumps(self.url)
            script += 'r2.cmd("f httpok=" + Number(response.status === 201 && response.body === "hello món"))'
            r2.cmd("'js " + script)
            self.assertEqual(r2.cmd('?v httpok').strip(), '0x1')
            e = r2._exports
            e.r_sandbox_grain(33)  # socket + network, no exec/files
            e.r_sandbox_enable(1)
            self.assertEqual(self.call(r2, 'post')[0], 201)
            count = len(self.requests)
            for grain in (1, 32, 0):
                e.r_sandbox_grain(grain)
                self.assertIsNone(self.call(r2, 'get'))
                self.assertIsNone(self.call(r2, 'post'))
                self.assertEqual(len(self.requests), count)

    def test_http_file(self):
        with r2pipe_wasm.open(self.url, wasm=os.environ['R2PIPE_WASM_NETWORK'], network=True) as r2:
            self.assertEqual(r2.cmdj('pxj 3'), [144, 0, 195])
