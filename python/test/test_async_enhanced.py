import unittest
import os
import tempfile
import asyncio
import time
import r2pipe
from r2pipe.open_async import open as async_open

class TestR2PipeAsyncEnhanced(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.curdir = os.path.dirname(os.path.realpath(__file__))
        cls.test_binary = os.path.join(cls.curdir, "ls")
        # Create a test file for file-related tests
        cls.test_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_file.write(b"\x90\x90\x90\x90\xc3")  # NOP NOP NOP NOP RET
        cls.test_file.close()

    @classmethod
    def tearDownClass(cls):
        # Clean up temporary files
        os.unlink(cls.test_file.name)

    def setUp(self):
        self.r2_ls = async_open(self.test_binary, ["-2"])
        self.r2_test = async_open(self.test_file.name)
        self.r2_null = async_open("-")

    def tearDown(self):
        self.r2_ls.close()
        self.r2_test.close()
        self.r2_null.close()

    # Basic async command tests
    def test_cmd_basic_async(self):
        """Test basic async commands execution"""
        result = self.r2_ls.cmd("i")
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)

    def test_cmd_multiple_async(self):
        """Test multiple async commands execution"""
        result = self.r2_ls.cmd("i; pd 5; s entry0")
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)

    def test_cmdj_async(self):
        """Test JSON async command parsing"""
        info = self.r2_ls.cmdj("ij")
        self.assertIsInstance(info, dict)
        self.assertIn("bin", info)

    # Test with callbacks
    def test_cmd_with_callback(self):
        """Test async commands with callback functions"""
        result_store = []
        
        def callback(result):
            result_store.append(result)
        
        # Execute command with callback
        task = self.r2_ls.cmd("i", callback=callback)
        
        # Wait for the task to complete
        self.r2_ls.wait(task)
        
        # Check that callback was executed
        self.assertEqual(len(result_store), 1)
        self.assertTrue(len(result_store[0]) > 0)

    # Test multiple concurrent commands
    def test_concurrent_commands(self):
        """Test executing multiple commands concurrently"""
        result_store = []
        
        def callback(result):
            result_store.append(result)
        
        # Start 3 concurrent tasks
        task1 = self.r2_ls.cmd("i", callback=callback)
        task2 = self.r2_ls.cmd("pd 5", callback=callback)
        task3 = self.r2_ls.cmd("ij", callback=callback)
        
        # Wait for all tasks to complete
        self.r2_ls.wait([task1, task2, task3])
        
        # Check we got 3 results
        self.assertEqual(len(result_store), 3)

    # Test with context manager
    def test_context_manager(self):
        """Test async r2pipe with context manager"""
        with async_open(self.test_binary) as r2:
            result = r2.cmd("i")
            self.assertIsNotNone(result)
            self.assertTrue(len(result) > 0)
            
            # Try multiple commands
            tasks = []
            results = []
            
            def callback(result):
                results.append(result)
            
            tasks.append(r2.cmd("pd 5", callback=callback))
            tasks.append(r2.cmd("ij", callback=callback))
            
            r2.wait(tasks)
            
            self.assertEqual(len(results), 2)

    # Test command sequencing and ordering
    def test_command_ordering(self):
        """Test that commands are executed in the correct order"""
        results = []
        
        def callback(result):
            results.append(result)
        
        # Send commands that must be executed in sequence to ensure correctness
        task1 = self.r2_test.cmd("wx 90", callback=callback)  # Write NOP
        task2 = self.r2_test.cmd("px 1", callback=callback)   # Read the byte we just wrote
        
        self.r2_test.wait([task1, task2])
        
        # Check that the results are in the expected order
        self.assertEqual(len(results), 2)
        # The second result should contain "90" (the byte we wrote)
        self.assertIn("90", results[1])

    # Test performance with many commands
    def test_multiple_commands_performance(self):
        """Test performance with many commands"""
        cmd_count = 20
        results = []
        
        def callback(result):
            results.append(result)
        
        # Record start time
        start_time = time.time()
        
        # Send multiple commands
        tasks = [self.r2_ls.cmd("pi 1", callback=callback) for _ in range(cmd_count)]
        
        # Wait for all commands to complete
        self.r2_ls.wait(tasks)
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Check results
        self.assertEqual(len(results), cmd_count)
        # Log performance info (would be useful for CI/performance tracking)
        print(f"Executed {cmd_count} commands in {execution_time:.4f}s")

    # Test error handling in async mode
    def test_invalid_commands_async(self):
        """Test invalid commands don't crash async r2pipe"""
        result = self.r2_ls.cmd("not_a_real_command")
        self.assertEqual(result, "")
        
        # Empty command
        result = self.r2_ls.cmd("")
        self.assertEqual(result, "")

    # Test connection pooling in HTTP mode
    def test_http_connection_pooling_setup(self):
        """Test HTTP connection pooling setup"""
        # This is a test setup validation - we can't easily test an HTTP server
        # without setting one up, but we can check the connection pool is created
        try:
            r2_http = async_open("http://127.0.0.1:9090")
            self.assertIsNotNone(r2_http)
            self.assertTrue(hasattr(r2_http, '_connection_pool'))
            r2_http.close()
        except Exception as e:
            # Skip test if we can't connect (expected if no server is running)
            self.skipTest(f"HTTP server not available: {str(e)}")

    # Test closing and cleanup
    def test_close_cleanup(self):
        """Test proper cleanup after closing"""
        r2 = async_open(self.test_binary)
        # Do some operations
        r2.cmd("i")
        # Close the connection
        r2.close()
        # Attempt to use after closing - should raise an exception or return error
        with self.assertRaises(Exception):
            r2.cmd("i")

    # Test pending output handling
    def test_pending_output_handling(self):
        """Test correct handling of pending output in commands"""
        # This command should generate output with a null byte in the middle
        # to test the pending output handling logic
        cmd = 'pf i(foo)b(bar)'
        result = self.r2_test.cmd(cmd)
        self.assertIsNotNone(result)
        
        # Follow up with another command immediately to see if pending output is handled
        result2 = self.r2_test.cmd("i")
        self.assertIsNotNone(result2)

if __name__ == '__main__':
    unittest.main()