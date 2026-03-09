import unittest
import os
import tempfile
import time
import sys
import signal
import threading
import r2pipe
from r2pipe.open_sync import open as sync_open
from r2pipe.open_async import open as async_open

class TestR2PipeErrorHandling(unittest.TestCase):
    """Tests focused on error handling and edge cases in r2pipe"""

    @classmethod
    def setUpClass(cls):
        cls.curdir = os.path.dirname(os.path.realpath(__file__))
        cls.test_binary = os.path.join(cls.curdir, "ls")
        # Create a test file with invalid binary content
        cls.invalid_file = tempfile.NamedTemporaryFile(delete=False)
        cls.invalid_file.write(b"This is not a valid executable file")
        cls.invalid_file.close()
        # Create a test file with valid binary content
        cls.valid_file = tempfile.NamedTemporaryFile(delete=False)
        cls.valid_file.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100)  # Simple ELF header
        cls.valid_file.close()
        # Create a nonexistent path
        cls.nonexistent_file = "/tmp/r2pipe_nonexistent_file_" + str(int(time.time()))

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.invalid_file.name)
        os.unlink(cls.valid_file.name)
        if os.path.exists(cls.nonexistent_file):
            os.unlink(cls.nonexistent_file)

    # Test error handling in sync mode
    def test_sync_nonexistent_file(self):
        """Test opening a nonexistent file in sync mode"""
        with self.assertRaises(Exception):
            r2 = sync_open(self.nonexistent_file, [])

    def test_sync_invalid_file(self):
        """Test opening an invalid binary file in sync mode"""
        r2 = sync_open(self.invalid_file.name, [])
        try:
            result = r2.cmd("iI")
            self.assertIsNotNone(result)
        finally:
            r2.quit()

    def test_sync_command_timeout(self):
        """Test command timeout handling in sync mode"""
        r2 = sync_open(self.test_binary, [])
        try:
            start_time = time.time()
            result = r2.cmd("px 10000000")
            elapsed = time.time() - start_time
            self.assertTrue(elapsed < 30)
        finally:
            r2.quit()

    def test_sync_process_killed(self):
        """Test handling when r2 process is killed externally"""
        r2 = sync_open(self.test_binary, [])
        if hasattr(r2, 'process'):
            pid = r2.process.pid
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
            # After process is killed, cmd returns empty or raises
            try:
                result = r2.cmd("i")
                self.assertEqual(result, "")
            except Exception:
                pass  # raising is also acceptable
        else:
            self.skipTest("Process attribute not available")

    def test_sync_invalid_commands(self):
        """Test invalid r2 commands in sync mode"""
        r2 = sync_open(self.test_binary, [])
        try:
            result = r2.cmd("not_a_valid_r2_command")
            self.assertEqual(result, "")

            result = r2.cmd("")
            self.assertEqual(result, "")

            with self.assertRaises(Exception):
                r2.cmd(None)
        finally:
            r2.quit()

    def test_sync_large_command(self):
        """Test very large commands in sync mode"""
        r2 = sync_open(self.test_binary, [])
        try:
            large_cmd = "px " + "1" * 1000
            result = r2.cmd(large_cmd)
            self.assertIsNotNone(result)
        finally:
            r2.quit()

    def test_sync_large_output(self):
        """Test commands with very large output in sync mode"""
        r2 = sync_open(self.test_binary, [])
        try:
            result = r2.cmd("px 100000")
            self.assertTrue(len(result) > 10000)
        finally:
            r2.quit()

    def test_sync_binary_output(self):
        """Test handling binary data in command output in sync mode"""
        r2 = sync_open(self.test_binary, [])
        try:
            result = r2.cmd("p8 100")
            self.assertTrue(all(c in "0123456789abcdef" for c in result.strip()))
        finally:
            r2.quit()

    def test_sync_multiple_instances(self):
        """Test running multiple r2pipe instances in sync mode"""
        instances = [sync_open(self.test_binary, []) for _ in range(3)]
        try:
            results = [instance.cmd("i") for instance in instances]
            for result in results:
                self.assertIsNotNone(result)
                self.assertTrue(len(result) > 0)
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[1], results[2])
        finally:
            for instance in instances:
                instance.quit()

    def test_sync_concurrent_commands(self):
        """Test concurrent commands in sync mode (should be thread-safe)"""
        r2 = sync_open(self.test_binary, [])
        try:
            results = []
            def run_command(cmd):
                results.append(r2.cmd(cmd))

            threads = []
            for i in range(10):
                cmd = f"pd {i*10+1}"
                t = threading.Thread(target=run_command, args=(cmd,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            self.assertEqual(len(results), 10)
            for result in results:
                self.assertIsNotNone(result)
        finally:
            r2.quit()

    # Test error handling in async mode
    def test_async_nonexistent_file(self):
        """Test opening a nonexistent file in async mode"""
        r2 = async_open(self.nonexistent_file, [])
        # The open itself may succeed, but the first cmd will fail
        with self.assertRaises(Exception):
            r2.cmd("i")
        r2.close()

    def test_async_invalid_file(self):
        """Test opening an invalid binary file in async mode"""
        r2 = async_open(self.invalid_file.name, [])
        try:
            result = r2.cmd("iI")
            self.assertIsNotNone(result)
        finally:
            r2.close()

    def test_async_command_timeout(self):
        """Test command timeout handling in async mode"""
        r2 = async_open(self.test_binary, [])
        try:
            start_time = time.time()
            result = r2.cmd("px 10000000")
            elapsed = time.time() - start_time
            self.assertTrue(elapsed < 30)
        finally:
            r2.close()

    def test_async_invalid_commands(self):
        """Test invalid r2 commands in async mode"""
        r2 = async_open(self.test_binary, [])
        try:
            result = r2.cmd("not_a_valid_r2_command")
            self.assertEqual(result, "")

            result = r2.cmd("")
            self.assertEqual(result, "")

            with self.assertRaises(Exception):
                r2.cmd(None)
        finally:
            r2.close()

    def test_async_large_command(self):
        """Test very large commands in async mode"""
        r2 = async_open(self.test_binary, [])
        try:
            large_cmd = "px " + "1" * 1000
            result = r2.cmd(large_cmd)
            self.assertIsNotNone(result)
        finally:
            r2.close()

    def test_async_command_ordering(self):
        """Test command ordering in async mode"""
        r2 = async_open("malloc://1024", [])
        try:
            results = []
            def callback(result):
                results.append(result)
            r2.cmd("e asm.arch=x86", callback=callback)
            r2.cmd("e asm.bits=32", callback=callback)
            r2.cmd("wx 90", callback=callback)
            r2.cmd("pd 1 @e:scr.color=0", callback=callback)
            self.assertEqual(len(results), 4)
            self.assertIn("nop", results[3].lower())
        finally:
            r2.close()

    def test_async_callback_error_handling(self):
        """Test error handling in async callbacks"""
        r2 = async_open(self.test_binary, [])
        try:
            error_occurred = threading.Event()

            def buggy_callback(result):
                error_occurred.set()
                raise ValueError("Intentional error in callback")

            # Buggy callback should not prevent further commands
            try:
                r2.cmd("i", callback=buggy_callback)
            except ValueError:
                pass
            self.assertTrue(error_occurred.is_set())

            # Subsequent commands should still work
            result = r2.cmd("i")
            self.assertIsNotNone(result)
        finally:
            r2.close()

    def test_tcp_error_handling_setup(self):
        """Test TCP error handling setup"""
        with self.assertRaises(Exception):
            r2 = r2pipe.open("tcp://127.0.0.1:9999")

    def test_http_error_handling_setup(self):
        """Test HTTP error handling setup - http open doesn't fail until cmd"""
        r2 = r2pipe.open("http://127.0.0.1:9999")
        result = r2.cmd("i")
        self.assertIsNone(result)

    def test_stdin_handling(self):
        """Test using stdin mode with dash"""
        r2 = r2pipe.open("-")
        try:
            result = r2.cmd("?e test")
            self.assertEqual(result, "test\n")
        finally:
            r2.quit()

    def test_quit_multiple_times(self):
        """Test calling quit multiple times"""
        r2 = r2pipe.open(self.test_binary)
        r2.quit()
        r2.quit()

    def test_close_multiple_times(self):
        """Test calling close multiple times with async interface"""
        r2 = async_open(self.test_binary, [])
        r2.close()
        r2.close()

    def test_syscmd(self):
        """Test syscmd runs shell commands"""
        r2 = sync_open(self.test_binary, [])
        try:
            result = r2.syscmd("echo hello")
            self.assertIn(b"hello", result)
        finally:
            r2.quit()

    def test_syscmdj(self):
        """Test syscmdj parses JSON from shell"""
        r2 = sync_open(self.test_binary, [])
        try:
            result = r2.syscmdj('echo \'{"a":1}\'')
            self.assertIsInstance(result, dict)
            self.assertEqual(result["a"], 1)
        finally:
            r2.quit()

    def test_syscmdj_invalid(self):
        """Test syscmdj with invalid JSON"""
        r2 = sync_open(self.test_binary, [])
        try:
            result = r2.syscmdj("echo 'not json'")
            self.assertIsNone(result)
        finally:
            r2.quit()

if __name__ == '__main__':
    unittest.main()
