import unittest
import r2pipe
from r2pipe.native import *
import ctypes


class TestR2PipeUnit(unittest.TestCase):

    def test_version(self):
        self.assertEqual(r2pipe.version(), r2pipe.VERSION)

    def test_native_r2lib(self):
        lib = r2lib()
        if sys.platform.startswith("win"):
            self.assertIsInstance(lib, ctypes.WinDLL)
        else:
            self.assertIsInstance(lib, ctypes.CDLL)
    
    def test_native_rcore(self):
        c = RCore()
        value = c.cmd_str("o /bin/ls; s entry0;pd 1~1[2]")
        c.free()
        self.assertEqual(value, 'push\n')
