import unittest
import os
import tempfile
import json
import r2pipe
from r2pipe.open_sync import open

class TestR2PipeSyncEnhanced(unittest.TestCase):

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
        self.r2_ls = r2pipe.open(self.test_binary, ["-2"])
        self.r2_test = r2pipe.open(self.test_file.name, ["-ax86"])
        self.r2_null = r2pipe.open("malloc://1024")

    def tearDown(self):
        self.r2_ls.quit()
        self.r2_test.quit()
        self.r2_null.quit()

    # Basic command tests
    def test_cmd_basic_commands(self):
        """Test various basic r2 commands"""
        # Test standard commands
        self.assertIsNotNone(self.r2_ls.cmd("i"))
        self.assertIsNotNone(self.r2_ls.cmd("iz"))
        self.assertIsNotNone(self.r2_ls.cmd("pd 10"))
        
    def test_cmd_multiple_commands(self):
        """Test running multiple commands sequentially"""
        # Test multiple commands
        result = self.r2_ls.cmd("i; pd 5; s entry0")
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)
        
        # Test multiple commands with newline
        result = self.r2_ls.cmd("i\npd 5\ns entry0")
        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)

    # JSON command tests
    def test_cmdj_parsing(self):
        """Test JSON command parsing with cmdj"""
        info = self.r2_ls.cmdj("ij")
        self.assertIsInstance(info, dict)
        self.assertIn("bin", info)
        
        # Test with a command that returns an array
        disasm = self.r2_ls.cmdj("pdj 5")
        self.assertIsInstance(disasm, list)
        
    def test_cmdj_invalid_json(self):
        """Test cmdj with commands that don't return valid JSON"""
        # Should not raise an exception but return None
        result = self.r2_ls.cmdj("px 10")
        self.assertIsNone(result)

    # Test cmdJ (Python object conversion)
    def test_cmdJ_object_conversion(self):
        """Test cmdJ Python object conversion"""
        info = self.r2_ls.cmdJ("ij")
        # Check if we get a namedtuple or similar object
        self.assertTrue(hasattr(info, "bin"))
        self.assertTrue(hasattr(info.bin, "machine"))

    # Test cache functionality
    def test_cache_functionality(self):
        """Test cache functionality"""
        self.r2_ls.use_cache = True
        cmd = "ij"
        
        # Cache should be empty initially
        self.assertEqual(len(self.r2_ls.cache), 0)
        
        # First call should add to cache
        res1 = self.r2_ls.cmd(cmd)
        self.assertEqual(len(self.r2_ls.cache), 1)
        self.assertIn(cmd, self.r2_ls.cache)
        
        # Second call should use cache
        res2 = self.r2_ls.cmd(cmd)
        self.assertEqual(res1, res2)
        
        # Invalidate cache and check it's empty
        self.r2_ls.invalidate_cache()
        self.assertEqual(len(self.r2_ls.cache), 0)
        
        # Turn off cache
        self.r2_ls.use_cache = False
        self.r2_ls.cmd(cmd)
        self.assertEqual(len(self.r2_ls.cache), 0)

    # Test with custom file
    def test_small_binary_operations(self):
        """Test operations on a small custom binary"""
        # Write some bytes
        self.r2_test.cmd("wx 9090909090c3")
        
        # Check the bytes have been written
        bytes_str = self.r2_test.cmdj("p8j 6")
        expected = [0x90, 0x90, 0x90, 0x90, 0x90, 0xc3]
        self.assertEqual(bytes_str, expected)
        
        # Test disassembly
        disasm = self.r2_test.cmd("pd 2").splitlines()
        self.assertEqual(len(disasm), 2)
        self.assertIn("nop", disasm[0].lower())

    # Error handling tests
    def test_invalid_commands(self):
        """Test invalid commands don't crash r2pipe"""
        # Command that doesn't exist
        result = self.r2_ls.cmd("not_a_real_command")
        self.assertEqual(result, "")
        
        # Empty command
        result = self.r2_ls.cmd("")
        self.assertEqual(result, "")

    def test_large_output(self):
        """Test commands with large output"""
        # Generate a large output
        large_output = self.r2_ls.cmd("px 10000")
        self.assertTrue(len(large_output) > 1000)

    # System command tests
    def test_syscmd(self):
        """Test syscmd functionality"""
        result = self.r2_ls.syscmd("echo test")
        self.assertIn(b"test", result)

    def test_syscmdj(self):
        """Test syscmdj functionality with valid JSON"""
        # Create a JSON string to echo
        test_json = '{"test": "value"}'
        result = self.r2_ls.syscmdj(f"echo '{test_json}'")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["test"], "value")

    def test_syscmdj_invalid(self):
        """Test syscmdj with invalid JSON"""
        # Should handle invalid JSON gracefully
        result = self.r2_ls.syscmdj("echo 'not json'")
        self.assertIsNone(result)

    # Test different open modes
    def test_open_with_additional_parameters(self):
        """Test opening with various parameters"""
        # No analysis
        r2_no_analysis = r2pipe.open(self.test_binary, ["-n"])
        self.assertIsNotNone(r2_no_analysis)
        r2_no_analysis.quit()
        
        # Multiple flags
        r2_multi_params = r2pipe.open(self.test_binary, ["-n", "-q"])
        self.assertIsNotNone(r2_multi_params)
        r2_multi_params.quit()

if __name__ == '__main__':
    unittest.main()
