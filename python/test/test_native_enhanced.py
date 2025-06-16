import unittest
import os
import sys
import tempfile
import ctypes
import r2pipe
from r2pipe.native import *

class TestR2PipeNativeEnhanced(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.curdir = os.path.dirname(os.path.realpath(__file__))
        cls.test_binary = os.path.join(cls.curdir, "ls")
        # Create a small test binary file
        cls.test_file = tempfile.NamedTemporaryFile(delete=False)
        cls.test_file.write(b"\x90\x90\x90\x90\xc3")  # NOP NOP NOP NOP RET
        cls.test_file.close()

    @classmethod
    def tearDownClass(cls):
        # Clean up temporary files
        os.unlink(cls.test_file.name)

    def setUp(self):
        # Skip tests if native library isn't available
        try:
            self.lib = r2lib()
            if self.lib is None:
                self.skipTest("r_core library not available")
        except:
            self.skipTest("Error loading r_core library")

    # Test r2lib() function
    def test_r2lib_loading(self):
        """Test r2lib() function for loading the native library"""
        lib = r2lib()
        self.assertIsNotNone(lib)
        
        # Check the library type based on platform
        if sys.platform.startswith("win"):
            self.assertIsInstance(lib, ctypes.WinDLL)
        else:
            self.assertIsInstance(lib, ctypes.CDLL)

    # Test RCore class
    def test_rcore_initialization(self):
        """Test RCore initialization and free"""
        core = RCore()
        self.assertIsNotNone(core)
        self.assertIsNotNone(core._o)
        core.free()

    def test_rcore_cmd_str(self):
        """Test RCore.cmd_str() function"""
        core = RCore()
        
        # Test with various commands
        result = core.cmd_str("?e hello")
        self.assertEqual(result, "hello\n")
        
        # Open a file
        core.cmd_str(f"o {self.test_binary}")
        
        # Run commands on the opened file
        info = core.cmd_str("ij")
        self.assertTrue(len(info) > 0)
        self.assertTrue(info.startswith("{"))
        
        core.free()

    def test_rcore_multiple_instances(self):
        """Test multiple RCore instances running simultaneously"""
        core1 = RCore()
        core2 = RCore()
        
        # Open different files in each instance
        core1.cmd_str(f"o {self.test_binary}")
        core2.cmd_str(f"o {self.test_file.name}")
        
        # Get info from both
        info1 = core1.cmd_str("ij")
        info2 = core2.cmd_str("ij")
        
        # Should get different results
        self.assertNotEqual(info1, info2)
        
        core1.free()
        core2.free()

    # Test ccall:// protocol with RCore
    def test_ccall_protocol(self):
        """Test ccall:// protocol which uses native bindings"""
        r2 = r2pipe.open(f"ccall://{self.test_binary}")
        
        # Test basic commands
        result = r2.cmd("i")
        self.assertTrue(len(result) > 0)
        
        # Test JSON commands
        info = r2.cmdj("ij")
        self.assertIsInstance(info, dict)
        
        r2.quit()

    # Test AddressHolder class
    def test_address_holder(self):
        """Test AddressHolder descriptor"""
        # Create a test class using AddressHolder
        class TestObject(object):
            address = AddressHolder()
            
            def __init__(self):
                pass
        
        obj = TestObject()
        # First access should compute and store the address
        addr1 = obj.address
        self.assertIsNotNone(addr1)
        
        # Second access should return the stored address
        addr2 = obj.address
        self.assertEqual(addr1, addr2)
        
        # Setting the address should update it
        new_addr = 12345
        obj.address = new_addr
        self.assertEqual(obj.address, new_addr)

    # Test WrappedRMethod class
    def test_wrapped_r_method(self):
        """Test WrappedRMethod class"""
        # Skip if library not available
        if r2lib() is None:
            self.skipTest("r_core library not available")
        
        # Create a wrapped method (r_core_cmd_str)
        method = WrappedRMethod("r_core_cmd_str", "c_void_p, c_char_p", "c_char_p")
        
        # Method should have had its args set
        self.assertTrue(method.args_set)
        
        # Create an RCore instance to test the method
        core = RCore()
        
        # Call the method directly
        result = method(core._o, "?e test")
        self.assertEqual(result, "test\n")
        
        core.free()

    # Test WrappedApiMethod class
    def test_wrapped_api_method(self):
        """Test WrappedApiMethod class"""
        # Skip if library not available
        if r2lib() is None:
            self.skipTest("r_core library not available")
        
        # Create a raw method
        r_method = WrappedRMethod("r_core_cmd_str", "c_void_p, c_char_p", "c_char_p")
        
        # Create a wrapped API method
        api_method = WrappedApiMethod(r_method, "c_char_p", None)
        
        # Create an RCore instance to test
        core = RCore()
        
        # Set the core object in the API method
        api_method._o = core._o
        
        # Call the method
        result = api_method("?e api_test")
        self.assertEqual(result, "api_test\n")
        
        core.free()

    # Test register function
    def test_register_function(self):
        """Test register() function"""
        # Skip if library not available
        if r2lib() is None:
            self.skipTest("r_core library not available")
        
        # Register a method
        wrapped_method, raw_method = register(
            "r_core_cmd_str", "c_void_p, c_char_p", "c_char_p"
        )
        
        # Check that both methods are created
        self.assertIsInstance(wrapped_method, WrappedApiMethod)
        self.assertIsInstance(raw_method, WrappedRMethod)
        
        # Test with a complex return type
        wrapped_method, raw_method = register(
            "r_core_new", "", "RCore"
        )
        
        # Should have pointer return
        self.assertEqual(raw_method.ret, "POINTER(RCore)")
        self.assertEqual(wrapped_method.last, "contents")

    # Test error handling
    def test_native_errors(self):
        """Test error handling in native mode"""
        core = RCore()
        
        # Invalid command
        result = core.cmd_str("not_a_command")
        self.assertEqual(result, "")
        
        # Try to open a nonexistent file
        result = core.cmd_str("o /path/to/nonexistent/file")
        # Should not crash and should return some error message
        self.assertTrue(result.lower().find("error") != -1 or result.lower().find("cannot") != -1)
        
        core.free()

    # Test memory management
    def test_memory_management(self):
        """Test memory management and cleanup"""
        # Create multiple cores and free them
        cores = [RCore() for _ in range(5)]
        
        # Use each core
        for i, core in enumerate(cores):
            core.cmd_str(f"?e core{i}")
            
        # Free each core
        for core in cores:
            core.free()

if __name__ == '__main__':
    unittest.main()