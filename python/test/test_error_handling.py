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
        # Clean up temporary files
        os.unlink(cls.invalid_file.name)
        os.unlink(cls.valid_file.name)
        # Remove nonexistent file if it somehow got created
        if os.path.exists(cls.nonexistent_file):
            os.unlink(cls.nonexistent_file)

    # Test error handling in sync mode
    def test_sync_nonexistent_file(self):
        """Test opening a nonexistent file in sync mode"""
        with self.assertRaises(Exception):
            r2 = sync_open(self.nonexistent_file)

    def test_sync_invalid_file(self):
        """Test opening an invalid binary file in sync mode"""
        # This should not raise an exception, but some commands might fail
        r2 = sync_open(self.invalid_file.name)
        try:
            # Try some commands that might fail on invalid files
            result = r2.cmd("iI")
            self.assertTrue(result == "" or "Invalid" in result or "unknown" in result.lower())
        finally:
            r2.quit()

    def test_sync_command_timeout(self):
        """Test command timeout handling in sync mode"""
        r2 = sync_open(self.test_binary)
        try:
            # Create a command that takes a long time to execute
            start_time = time.time()
            result = r2.cmd("px 10000000")  # Large hexdump that takes time
            elapsed = time.time() - start_time
            # Verify command completed and didn't hang
            self.assertTrue(elapsed < 30)  # Should complete much faster
        finally:
            r2.quit()

    def test_sync_process_killed(self):
        """Test handling when r2 process is killed externally"""
        r2 = sync_open(self.test_binary)
        
        # Get the process and kill it forcefully
        if hasattr(r2, 'process'):
            pid = r2.process.pid
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)  # Give it time to die
            
            # Attempts to communicate should raise an exception or return error
            with self.assertRaises(Exception):
                r2.cmd("i")
        else:
            self.skipTest("Process attribute not available")

    def test_sync_invalid_commands(self):
        """Test invalid r2 commands in sync mode"""
        r2 = sync_open(self.test_binary)
        try:
            # Test with invalid command
            result = r2.cmd("not_a_valid_r2_command")
            self.assertEqual(result, "")  # Should return empty string
            
            # Test with empty command
            result = r2.cmd("")
            self.assertEqual(result, "")
            
            # Test with None command
            with self.assertRaises(Exception):
                r2.cmd(None)
        finally:
            r2.quit()

    def test_sync_large_command(self):
        """Test very large commands in sync mode"""
        r2 = sync_open(self.test_binary)
        try:
            # Create a very large command
            large_cmd = "px " + "1" * 1000  # Command with 1004 characters
            result = r2.cmd(large_cmd)
            self.assertIsNotNone(result)
        finally:
            r2.quit()

    def test_sync_large_output(self):
        """Test commands with very large output in sync mode"""
        r2 = sync_open(self.test_binary)
        try:
            # Command that produces large output
            result = r2.cmd("px 100000")
            self.assertTrue(len(result) > 10000)
        finally:
            r2.quit()

    def test_sync_binary_output(self):
        """Test handling binary data in command output in sync mode"""
        r2 = sync_open(self.test_binary)
        try:
            # Command that produces binary output
            result = r2.cmd("p8 100")  # Get raw bytes
            self.assertTrue(all(c in "0123456789abcdef" for c in result.strip()))
        finally:
            r2.quit()

    def test_sync_multiple_instances(self):
        """Test running multiple r2pipe instances in sync mode"""
        # Open multiple instances
        instances = [sync_open(self.test_binary) for _ in range(3)]
        
        try:
            # Run commands on all instances
            results = [instance.cmd("i") for instance in instances]
            
            # Each result should be valid
            for result in results:
                self.assertIsNotNone(result)
                self.assertTrue(len(result) > 0)
                
            # Results should be similar (same file)
            self.assertEqual(results[0], results[1])
            self.assertEqual(results[1], results[2])
        finally:
            # Clean up all instances
            for instance in instances:
                instance.quit()

    def test_sync_concurrent_commands(self):
        """Test concurrent commands in sync mode (should be thread-safe)"""
        r2 = sync_open(self.test_binary)
        try:
            # Create threads that run commands concurrently
            results = []
            def run_command(cmd):
                results.append(r2.cmd(cmd))
                
            threads = []
            for i in range(10):
                cmd = f"pd {i*10+1}"
                t = threading.Thread(target=run_command, args=(cmd,))
                threads.append(t)
                t.start()
                
            # Wait for all threads to complete
            for t in threads:
                t.join()
                
            # Check that we got 10 results
            self.assertEqual(len(results), 10)
            # And that they're all valid
            for result in results:
                self.assertIsNotNone(result)
        finally:
            r2.quit()

    # Test error handling in async mode
    def test_async_nonexistent_file(self):
        """Test opening a nonexistent file in async mode"""
        with self.assertRaises(Exception):
            r2 = async_open(self.nonexistent_file)

    def test_async_invalid_file(self):
        """Test opening an invalid binary file in async mode"""
        # This should not raise an exception, but some commands might fail
        r2 = async_open(self.invalid_file.name)
        try:
            # Try some commands that might fail on invalid files
            result = r2.cmd("iI")
            self.assertTrue(result == "" or "Invalid" in result or "unknown" in result.lower())
        finally:
            r2.close()

    def test_async_command_timeout(self):
        """Test command timeout handling in async mode"""
        r2 = async_open(self.test_binary)
        try:
            # Create a command that takes time to execute
            start_time = time.time()
            result = r2.cmd("px 10000000")  # Large hexdump that takes time
            elapsed = time.time() - start_time
            # Verify command completed and didn't hang
            self.assertTrue(elapsed < 30)  # Should complete much faster
        finally:
            r2.close()

    def test_async_invalid_commands(self):
        """Test invalid r2 commands in async mode"""
        r2 = async_open(self.test_binary)
        try:
            # Test with invalid command
            result = r2.cmd("not_a_valid_r2_command")
            self.assertEqual(result, "")  # Should return empty string
            
            # Test with empty command
            result = r2.cmd("")
            self.assertEqual(result, "")
            
            # Test with None command
            with self.assertRaises(Exception):
                r2.cmd(None)
        finally:
            r2.close()

    def test_async_large_command(self):
        """Test very large commands in async mode"""
        r2 = async_open(self.test_binary)
        try:
            # Create a very large command
            large_cmd = "px " + "1" * 1000  # Command with 1004 characters
            result = r2.cmd(large_cmd)
            self.assertIsNotNone(result)
        finally:
            r2.close()

    def test_async_command_ordering(self):
        """Test command ordering in async mode with potential race condition"""
        r2 = async_open(self.valid_file.name)
        try:
            # Sequence of commands that depends on order
            results = []
            
            def callback(result):
                results.append(result)
            
            # Create a series of commands that modify state
            task1 = r2.cmd("e asm.arch=x86", callback=callback)
            task2 = r2.cmd("e asm.bits=32", callback=callback)
            task3 = r2.cmd("wx 90", callback=callback)  # Write a NOP
            task4 = r2.cmd("pd 1", callback=callback)   # Disassemble it
            
            # Wait for all tasks
            r2.wait([task1, task2, task3, task4])
            
            # Last result should have NOP in it
            if len(results) >= 4:
                self.assertIn("nop", results[3].lower())
        finally:
            r2.close()

    def test_async_callback_error_handling(self):
        """Test error handling in async callbacks"""
        r2 = async_open(self.test_binary)
        try:
            error_occurred = threading.Event()
            
            def buggy_callback(result):
                # This callback will raise an exception
                raise ValueError("Intentional error in callback")
                
            def good_callback(result):
                # This should still run even if previous callback failed
                error_occurred.set()
                
            # Run commands with the callbacks
            task1 = r2.cmd("i", callback=buggy_callback)
            task2 = r2.cmd("i", callback=good_callback)
            
            # Wait for tasks to complete
            r2.wait([task1, task2])
            
            # The second callback should still run
            self.assertTrue(error_occurred.is_set())
        finally:
            r2.close()

    def test_tcp_error_handling_setup(self):
        """Test TCP error handling setup"""
        # Try to connect to a port that's likely not running r2
        with self.assertRaises(Exception):
            r2 = r2pipe.open("tcp://127.0.0.1:9999")

    def test_http_error_handling_setup(self):
        """Test HTTP error handling setup"""
        # Try to connect to a port that's likely not running r2 http server
        with self.assertRaises(Exception):
            r2 = r2pipe.open("http://127.0.0.1:9999")

    def test_stdin_handling(self):
        """Test using stdin mode with dash"""
        r2 = r2pipe.open("-")
        try:
            # Basic commands should work in stdin mode
            result = r2.cmd("?e test")
            self.assertEqual(result, "test\n")
        finally:
            r2.quit()

    def test_quit_multiple_times(self):
        """Test calling quit multiple times"""
        r2 = r2pipe.open(self.test_binary)
        r2.quit()
        # Calling quit again should not raise an exception
        r2.quit()
        
    def test_close_multiple_times(self):
        """Test calling close multiple times with async interface"""
        r2 = async_open(self.test_binary)
        r2.close()
        # Calling close again should not raise an exception
        r2.close()

if __name__ == '__main__':
    unittest.main()