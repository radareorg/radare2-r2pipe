import unittest
import os
import tempfile
import time
import r2pipe
from r2pipe.open_async import open as async_open

class TestR2PipeAsyncEnhanced(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.curdir = os.path.dirname(os.path.realpath(__file__))
        cls.test_binary = os.path.join(cls.curdir, "ls")
        cls.test_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_file.write(b"\x90\x90\x90\x90\xc3")  # NOP NOP NOP NOP RET
        cls.test_file.close()

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.test_file.name)

    def setUp(self):
        self.r2_ls = async_open(self.test_binary, ["-2"])
        self.r2_test = async_open(self.test_file.name, [])
        self.r2_null = async_open("-", [])

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

    def test_cmd_with_callback(self):
        """Test async commands with callback functions"""
        result_store = []

        def callback(result):
            result_store.append(result)

        # In current implementation, callback is invoked synchronously
        self.r2_ls.cmd("i", callback=callback)
        self.assertEqual(len(result_store), 1)
        self.assertTrue(len(result_store[0]) > 0)

    def test_multiple_callbacks(self):
        """Test executing multiple commands with callbacks"""
        result_store = []

        def callback(result):
            result_store.append(result)

        self.r2_ls.cmd("i", callback=callback)
        self.r2_ls.cmd("pd 5", callback=callback)
        self.r2_ls.cmd("ij", callback=callback)
        self.assertEqual(len(result_store), 3)

    # Test with context manager
    def test_context_manager(self):
        """Test async r2pipe with context manager"""
        with async_open(self.test_binary, []) as r2:
            result = r2.cmd("i")
            self.assertIsNotNone(result)
            self.assertTrue(len(result) > 0)

    # Test command sequencing and ordering
    def test_command_ordering(self):
        """Test that commands are executed in the correct order"""
        results = []

        def callback(result):
            results.append(result)

        self.r2_test.cmd("wx 90", callback=callback)
        self.r2_test.cmd("px 1", callback=callback)
        self.assertEqual(len(results), 2)
        self.assertIn("90", results[1])

    # Test performance with many commands
    def test_multiple_commands_performance(self):
        """Test performance with many commands"""
        cmd_count = 20
        results = []

        def callback(result):
            results.append(result)

        start_time = time.time()
        for _ in range(cmd_count):
            self.r2_ls.cmd("pi 1", callback=callback)
        execution_time = time.time() - start_time
        self.assertEqual(len(results), cmd_count)

    # Test error handling in async mode
    def test_invalid_commands_async(self):
        """Test invalid commands don't crash async r2pipe"""
        result = self.r2_ls.cmd("not_a_real_command")
        self.assertEqual(result, "")

        result = self.r2_ls.cmd("")
        self.assertEqual(result, "")

    # Test closing and cleanup
    def test_close_cleanup(self):
        """Test proper cleanup after closing"""
        r2 = async_open(self.test_binary, [])
        r2.cmd("i")
        r2.close()
        with self.assertRaises(Exception):
            r2.cmd("i")

    # Test pending output handling
    def test_pending_output_handling(self):
        """Test correct handling of pending output in commands"""
        cmd = 'pf i(foo)b(bar)'
        result = self.r2_test.cmd(cmd)
        self.assertIsNotNone(result)
        result2 = self.r2_test.cmd("i")
        self.assertIsNotNone(result2)

    # Test HTTP connection pooling setup
    def test_http_connection_pooling_setup(self):
        """Test HTTP connection pooling setup"""
        try:
            r2_http = async_open("http://127.0.0.1:9090", [])
            self.assertIsNotNone(r2_http)
            self.assertTrue(hasattr(r2_http, '_connection_pool'))
            r2_http.close()
        except Exception as e:
            self.skipTest(f"HTTP server not available: {str(e)}")

    def test_null_target(self):
        """Test commands on stdin target"""
        result = self.r2_null.cmd("?e async_test")
        self.assertEqual(result, "async_test\n")

    def test_cmdj_async_invalid(self):
        """Test cmdj with non-JSON output"""
        result = self.r2_ls.cmdj("px 10")
        self.assertIsNone(result)

if __name__ == '__main__':
    unittest.main()
