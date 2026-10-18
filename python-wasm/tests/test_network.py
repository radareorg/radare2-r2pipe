"""Real WASM networking and sandbox checks, against a local HTTP server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import socket
import tempfile
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import r2pipe_wasm
try:
    from wasmer import wat2wasm
    HAVE_WASMER = True
except ImportError:
    HAVE_WASMER = False


@unittest.skipUnless(HAVE_WASMER, "Wasmer native SDK not installed")
class SocketBridgeTest(unittest.TestCase):
    def test_real_socket_imports_and_default_denial(self):
        # A small guest exercises the Python ABI in CI without downloading radare2.
        signatures = {"connect": 5, "read": 3, "write": 3, "close": 1}
        declarations = "".join(
            f'(import "r2net" "{name}" (func ${name} (param {" ".join(["i32"] * count)}) (result i32)))'
            for name, count in signatures.items())
        exports = "".join(f'(export "net_{name}" (func ${name}))' for name in signatures)
        wat = '(module ' + declarations + exports + '''
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
        with tempfile.TemporaryDirectory() as temporary, socket.socket() as server:
            path = Path(temporary) / "network.wasm"
            path.write_bytes(wat2wasm(wat))
            server.bind(("127.0.0.1", 0))
            server.listen()
            server.settimeout(2)
            for enabled in (False, True):
                with r2pipe_wasm.open(wasm=path, network=enabled) as r2:
                    e = r2._exports
                    host = r2._allocate("127.0.0.1")
                    port = r2._allocate(str(server.getsockname()[1]))
                    data = r2._allocate("hello")
                    handle = e.net_connect(host, port, 6, 0, 2)
                    if not enabled:
                        self.assertEqual(handle, -1)
                        continue
                    self.assertGreater(handle, 0)
                    peer, _ = server.accept()
                    with peer:
                        peer.settimeout(2)
                        self.assertEqual(e.net_write(handle, data, 5), 5)
                        self.assertEqual(peer.recv(5), b"hello")
                        peer.sendall(b"world")
                        self.assertEqual(e.net_read(handle, 65535, 5), -1)
                        self.assertEqual(e.net_read(handle, data, 5), 5)
                        self.assertEqual(r2._read_string(data), "world")
                    self.assertEqual(e.net_close(handle), 0)
                    self.assertFalse(r2._network.sockets)


@unittest.skipUnless(os.environ.get("R2PIPE_WASM_NETWORK"), "Set R2PIPE_WASM_NETWORK to a wasi-api-net build")
class NetworkTest(unittest.TestCase):
    def setUp(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(bytes.fromhex("9090c3"))
            def log_message(self, *_args):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}/sample"
        self.wasm = os.environ["R2PIPE_WASM_NETWORK"]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_http_file_and_opt_in(self):
        with r2pipe_wasm.open(self.url, wasm=self.wasm, network=True) as r2:
            self.assertEqual(r2.cmdj("pxj 3"), [144, 144, 195])
        with self.assertRaises(OSError):
            r2pipe_wasm.open(self.url, wasm=self.wasm)

    def test_sandbox_and_socket_cleanup(self):
        with r2pipe_wasm.open(wasm=self.wasm, network=True) as r2:
            e = r2._exports
            host = r2._allocate("localhost")
            remote = r2._allocate("127.example.invalid")
            port = r2._allocate(str(self.server.server_port))
            buf = r2._allocate("GET / HTTP/1.0\r\n\r\n")
            client = e.r_socket_new(0)
            try:
                e.r_sandbox_grain(1)  # local sockets only
                e.r_sandbox_enable(1)
                self.assertEqual(e.r_socket_connect(client, remote, port, 6, 2), 0)
                self.assertFalse(r2._network.sockets)
                self.assertEqual(e.r_socket_connect(client, host, port, 6, 2), 1)
                self.assertEqual(len(r2._network.sockets), 1)
                e.r_sandbox_grain(0)  # revoke access to an existing socket
                self.assertEqual(e.r_socket_write(client, buf, 1), -1)
                self.assertEqual(e.r_socket_read(client, buf, 1), -1)
                self.assertEqual(e.r_socket_ready(client, 0, 0), -1)
                self.assertEqual(e.r_socket_listen(client, port, 0), 0)
                self.assertEqual(e.r_socket_accept(client), 0)
                self.assertEqual(e.r_socket_connect(client, host, port, 6, 2), 0)
            finally:
                e.r_socket_free(client)
                for pointer in (host, remote, port, buf):
                    e.free(pointer)
            self.assertFalse(r2._network.sockets)

    def test_udp_and_tcp_listener(self):
        with r2pipe_wasm.open(wasm=self.wasm, network=True) as r2, socket.socket(type=socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", 0))
            udp.settimeout(2)
            e = r2._exports
            host = r2._allocate("127.0.0.1")
            port = r2._allocate(str(udp.getsockname()[1]))
            data = r2._allocate("hello")
            client = e.r_socket_new(0)
            listener = e.r_socket_new(0)
            try:
                self.assertEqual(e.r_socket_connect(client, host, port, 17, 2), 1)
                self.assertEqual(e.r_socket_write(client, data, 5), 5)
                packet, source = udp.recvfrom(16)
                self.assertEqual(packet, b"hello")
                udp.sendto(b"world", source)
                self.assertEqual(e.r_socket_read(client, data, 5), 5)
                self.assertEqual(r2._read_string(data), "world")
                e.r_socket_free(client)
                client = 0
                zero = r2._allocate("0")
                self.assertEqual(e.r_socket_listen(listener, zero, 0), 1)
                address = next(iter(r2._network.sockets.values())).getsockname()
                with socket.create_connection(("127.0.0.1", address[1]), timeout=2) as peer:
                    accepted = e.r_socket_accept(listener)
                    self.assertNotEqual(accepted, 0)
                    try:
                        self.assertEqual(e.r_socket_write(accepted, data, 5), 5)
                        self.assertEqual(peer.recv(5), b"world")
                    finally:
                        e.r_socket_free(accepted)
                e.free(zero)
            finally:
                e.r_socket_free(client)
                e.r_socket_free(listener)
                for pointer in (host, port, data):
                    e.free(pointer)

    def test_quit_closes_unclaimed_handles(self):
        r2 = r2pipe_wasm.open(wasm=self.wasm, network=True)
        host, port = r2._allocate("127.0.0.1"), r2._allocate(str(self.server.server_port))
        bridge = r2._network
        try:
            handle = bridge.connect(host, port, 6, 0, 2)
            self.assertGreater(handle, 0)
            sock = bridge.sockets[handle]
        finally:
            r2._exports.free(host)
            r2._exports.free(port)
            r2.quit()
        self.assertEqual(sock.fileno(), -1)
        self.assertFalse(bridge.sockets)


if __name__ == "__main__":
    unittest.main()
