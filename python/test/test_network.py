#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for r2pipe network functionality using mock servers
"""

import unittest
import os
import sys
import time
import threading
import subprocess
import r2pipe
import signal
from r2pipe.open_sync import open as sync_open
from r2pipe.open_async import open as async_open

# Path to mock server module
MOCK_SERVER_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "mock_r2_server.py")

# Default ports for test servers
TEST_HTTP_PORT = 9191
TEST_TCP_PORT = 9181

class TestR2PipeNetwork(unittest.TestCase):
    """Test r2pipe network functionality with mock servers"""

    @classmethod
    def setUpClass(cls):
        """Start mock servers before tests"""
        # Start HTTP and TCP mock servers
        cls.mock_server_proc = subprocess.Popen(
            [sys.executable, MOCK_SERVER_PATH, "--http", str(TEST_HTTP_PORT), "--tcp", str(TEST_TCP_PORT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        
        # Give servers time to start
        time.sleep(1)
        
        # Check if servers started successfully
        if cls.mock_server_proc.poll() is not None:
            raise Exception("Failed to start mock servers")

    @classmethod
    def tearDownClass(cls):
        """Stop mock servers after tests"""
        if cls.mock_server_proc:
            # Send SIGTERM to the mock server
            cls.mock_server_proc.terminate()
            # Wait for process to end
            cls.mock_server_proc.wait(timeout=5)
            # Kill if still running
            if cls.mock_server_proc.poll() is None:
                cls.mock_server_proc.kill()

    # HTTP tests
    def test_http_sync_basic(self):
        """Test HTTP connection in sync mode"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            # Test basic command
            result = r2.cmd("i")
            self.assertTrue(result and "arch" in result)
            
            # Test JSON command
            info = r2.cmdj("ij")
            self.assertIsInstance(info, dict)
            self.assertIn("core", info)
            self.assertIn("bin", info)
        finally:
            r2.quit()

    def test_http_sync_multiple_commands(self):
        """Test multiple commands over HTTP in sync mode"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            # Test combined commands
            result = r2.cmd("?e hello; ?e world")
            self.assertEqual(result, "hello\nworld\n")
            
            # Test with newlines
            result = r2.cmd("?e hello\n?e world")
            self.assertEqual(result, "hello\nworld\n")
        finally:
            r2.quit()

    def test_http_sync_parameterized_commands(self):
        """Test parameterized commands over HTTP in sync mode"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            # Test pd command with parameter
            result = r2.cmd("pd 3")
            self.assertTrue(result and result.count("push") >= 2)
            
            # Test JSON disassembly
            disasm = r2.cmdj("pdj 2")
            self.assertIsInstance(disasm, list)
            self.assertEqual(len(disasm), 2)
            
            # Test hex dump
            hex_dump = r2.cmd("px 32")
            self.assertTrue(hex_dump and "0x00400000" in hex_dump)
        finally:
            r2.quit()

    # TCP tests
    def test_tcp_sync_basic(self):
        """Test TCP connection in sync mode"""
        r2 = sync_open(f"tcp://127.0.0.1:{TEST_TCP_PORT}")
        try:
            # Test basic command
            result = r2.cmd("i")
            self.assertTrue(result and "arch" in result)
            
            # Test JSON command
            info = r2.cmdj("ij")
            self.assertIsInstance(info, dict)
            self.assertIn("core", info)
            self.assertIn("bin", info)
        finally:
            r2.quit()

    def test_tcp_sync_multiple_commands(self):
        """Test multiple commands over TCP in sync mode"""
        r2 = sync_open(f"tcp://127.0.0.1:{TEST_TCP_PORT}")
        try:
            # Test combined commands
            result = r2.cmd("?e hello; ?e world")
            self.assertEqual(result, "hello\nworld\n")
            
            # Test with newlines
            result = r2.cmd("?e hello\n?e world")
            self.assertEqual(result, "hello\nworld\n")
        finally:
            r2.quit()

    def test_tcp_sync_parameterized_commands(self):
        """Test parameterized commands over TCP in sync mode"""
        r2 = sync_open(f"tcp://127.0.0.1:{TEST_TCP_PORT}")
        try:
            # Test pd command with parameter
            result = r2.cmd("pd 3")
            self.assertTrue(result and result.count("0x004000") >= 2)
            
            # Test JSON disassembly
            disasm = r2.cmdj("pdj 2")
            self.assertIsInstance(disasm, list)
            self.assertEqual(len(disasm), 2)
            
            # Test hex dump
            hex_dump = r2.cmd("px 32")
            self.assertTrue(hex_dump and "0x00400000" in hex_dump)
        finally:
            r2.quit()

    # Async HTTP tests
    def test_http_async_basic(self):
        """Test HTTP connection in async mode"""
        r2 = async_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            # Test basic command
            result = r2.cmd("i")
            self.assertTrue(result and "arch" in result)
            
            # Test JSON command
            info = r2.cmdj("ij")
            self.assertIsInstance(info, dict)
            self.assertIn("core", info)
            self.assertIn("bin", info)
        finally:
            r2.close()

    def test_http_async_with_callbacks(self):
        """Test HTTP with callbacks in async mode"""
        r2 = async_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        
        results = []
        def callback(result):
            results.append(result)
            
        try:
            # Execute commands with callbacks
            task1 = r2.cmd("i", callback=callback)
            task2 = r2.cmd("?e hello", callback=callback)
            
            # Wait for tasks to complete
            r2.wait([task1, task2])
            
            # Check we got two results
            self.assertEqual(len(results), 2)
            # First should be info output
            self.assertTrue("arch" in results[0])
            # Second should be echo output
            self.assertEqual(results[1], "hello\n")
        finally:
            r2.close()

    # Async TCP tests
    def test_tcp_async_basic(self):
        """Test TCP connection in async mode"""
        r2 = async_open(f"tcp://127.0.0.1:{TEST_TCP_PORT}")
        try:
            # Test basic command
            result = r2.cmd("i")
            self.assertTrue(result and "arch" in result)
            
            # Test JSON command
            info = r2.cmdj("ij")
            self.assertIsInstance(info, dict)
            self.assertIn("core", info)
            self.assertIn("bin", info)
        finally:
            r2.close()

    def test_tcp_async_with_callbacks(self):
        """Test TCP with callbacks in async mode"""
        r2 = async_open(f"tcp://127.0.0.1:{TEST_TCP_PORT}")
        
        results = []
        def callback(result):
            results.append(result)
            
        try:
            # Execute commands with callbacks
            task1 = r2.cmd("i", callback=callback)
            task2 = r2.cmd("?e hello", callback=callback)
            
            # Wait for tasks to complete
            r2.wait([task1, task2])
            
            # Check we got two results
            self.assertEqual(len(results), 2)
            # Results should contain info output and echo output
            self.assertTrue(any("arch" in r for r in results))
            self.assertTrue(any(r == "hello\n" for r in results))
        finally:
            r2.close()

    # Error handling tests
    def test_http_connection_errors(self):
        """Test HTTP connection error handling"""
        # Try to connect to wrong port
        with self.assertRaises(Exception):
            r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT + 100}")
            r2.cmd("i")  # Should not reach here

    def test_tcp_connection_errors(self):
        """Test TCP connection error handling"""
        # Try to connect to wrong port
        with self.assertRaises(Exception):
            r2 = sync_open(f"tcp://127.0.0.1:{TEST_TCP_PORT + 100}")
            r2.cmd("i")  # Should not reach here

    # Performance tests
    def test_http_performance(self):
        """Test HTTP performance with multiple commands"""
        r2 = sync_open(f"http://127.0.0.1:{TEST_HTTP_PORT}")
        try:
            # Execute multiple commands and measure time
            start_time = time.time()
            for i in range(10):
                r2.cmd(f"pd {i+1}")
            duration = time.time() - start_time
            
            # Just a log, not an assertion
            print(f"HTTP executed 10 commands in {duration:.4f}s")
        finally:
            r2.quit()

    def test_tcp_performance(self):
        """Test TCP performance with multiple commands"""
        r2 = sync_open(f"tcp://127.0.0.1:{TEST_TCP_PORT}")
        try:
            # Execute multiple commands and measure time
            start_time = time.time()
            for i in range(10):
                r2.cmd(f"pd {i+1}")
            duration = time.time() - start_time
            
            # Just a log, not an assertion
            print(f"TCP executed 10 commands in {duration:.4f}s")
        finally:
            r2.quit()

if __name__ == '__main__':
    unittest.main()