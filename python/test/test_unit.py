import unittest
import os

import r2pipe
from r2pipe.native import *
import ctypes


class TestR2PipeUnit(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.curdir = os.path.dirname(os.path.realpath(__file__))

    def test_version(self):
        self.assertEqual(r2pipe.version(), r2pipe.VERSION)

    def test_native_r2lib(self):
        lib = r2lib()
        if sys.platform.startswith("win"):
            self.assertIsInstance(lib, ctypes.WinDLL)
        else:
            self.assertIsInstance(lib, ctypes.CDLL)

    def test_race_io(self):
        os.system("sh race.sh");
    
    def test_native_rcore(self):
        c = RCore()
        value = c.cmd_str("o %s/ls; s entry0;pi 1 @e:scr.color=0" % self.curdir).strip()
        c.free()
        self.assertEqual(value, 'push rbp')
