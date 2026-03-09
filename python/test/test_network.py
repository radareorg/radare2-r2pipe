#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for r2pipe network functionality using mock servers.
These tests require the mock server to be running.
They are skipped if the server is not available.
"""

import unittest
import os
import sys
import time
import subprocess
import r2pipe
from r2pipe.open_sync import open as sync_open
from r2pipe.open_async import open as async_open

# Path to mock server module
MOCK_SERVER_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "mock_r2_server.py")

# Default ports for test servers
TEST_HTTP_PORT = 9191
TEST_TCP_PORT = 9181


def _server_available(port):
    """Check if a server is responding on a port"""
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=1)
        s.close()
        return True
    except (ConnectionRefusedError, OSError):
        return False


class TestR2PipeNetwork(unittest.TestCase):
    """Test r2pipe network functionality with mock servers"""

    _server_proc = None

    @classmethod
    def setUpClass(cls):
        """Start mock servers before tests"""
        cls._server_proc = subprocess.Popen(
            [sys.executable, MOCK_SERVER_PATH, "--http", str(TEST_HTTP_PORT), "--tcp", str(TEST_TCP_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Wait for servers to start
        for _ in range(20):
            if _server_available(TEST_HTTP_PORT) and _server_available(TEST_TCP_PORT):
                return
            time.sleep(0.2)
        # If we get here, servers didn't start
        cls._server_proc.terminate()
        cls._server_proc = None

    @classmethod
    def tearDownClass(cls):
        """Stop mock servers after tests"""
        if cls._server_proc:
            cls._server_proc.terminate()
            cls._server_proc.wait(timeout=5)

    def setUp(self):
        if self._server_proc is None or self._server_proc.poll() is not None:
            self.skipTest("Mock servers not available")

    # HTTP tests
    def test_http_sync_basic(self):
        """Test HTTP connection in sync mode"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            result = r2.cmd("i")
            self.assertTrue(result and "arch" in result)
        finally:
            r2.quit()

    def test_http_sync_json(self):
        """Test HTTP JSON command in sync mode"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            info = r2.cmdj("ij")
            self.assertIsInstance(info, dict)
            self.assertIn("core", info)
            self.assertIn("bin", info)
        finally:
            r2.quit()

    def test_http_sync_echo(self):
        """Test echo commands over HTTP"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            result = r2.cmd("?e hello")
            self.assertEqual(result, "hello\n")
        finally:
            r2.quit()

    def test_http_sync_hexdump(self):
        """Test hexdump command over HTTP"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            hex_dump = r2.cmd("px 32")
            self.assertTrue(hex_dump and "0x00400000" in hex_dump)
        finally:
            r2.quit()

    # Async HTTP tests
    def test_http_async_basic(self):
        """Test HTTP connection in async mode"""
        r2 = async_open(f"http://127.0.0.1:{TEST_HTTP_PORT}", [])
        try:
            result = r2.cmd("i")
            self.assertTrue(result and "arch" in result)
        finally:
            r2.close()

    def test_http_async_with_callback(self):
        """Test HTTP with callback in async mode"""
        r2 = async_open(f"http://127.0.0.1:{TEST_HTTP_PORT}", [])
        results = []
        def callback(result):
            results.append(result)
        try:
            r2.cmd("i", callback=callback)
            self.assertEqual(len(results), 1)
            self.assertTrue("arch" in results[0])
        finally:
            r2.close()

    # Error handling tests
    def test_http_connection_errors(self):
        """Test HTTP connection error handling"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT + 100}")
        result = r2.cmd("i")
        # HTTP mode returns None on connection failure
        self.assertIsNone(result)

    def test_tcp_connection_errors(self):
        """Test TCP connection error handling"""
        with self.assertRaises(Exception):
            r2 = sync_open(f"tcp://127.0.0.1:{TEST_TCP_PORT + 100}")

    # Performance tests
    def test_http_performance(self):
        """Test HTTP performance with multiple commands"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            start_time = time.time()
            for i in range(5):
                r2.cmd("?e test")
            duration = time.time() - start_time
            self.assertTrue(duration < 10)
        finally:
            r2.quit()


if __name__ == '__main__':
    unittest.main()
