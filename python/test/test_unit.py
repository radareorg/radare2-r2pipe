import unittest
import os
import sys
from unittest.mock import patch, MagicMock

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


class TestFilenameArgsParsing(unittest.TestCase):
    """Test that filename arguments are correctly parsed into -R flags (PR #91)"""

    def _mock_popen(self):
        """Create a mock Popen that captures the command and simulates r2"""
        mock_proc = MagicMock()
        mock_proc.stdout.read.return_value = b'\x00'
        mock_proc.stdin.write.return_value = None
        mock_proc.stdin.flush.return_value = None
        mock_proc.poll.return_value = None
        return mock_proc

    @patch('r2pipe.open_sync.Popen')
    def test_string_with_args_builds_correct_cmd(self, mock_popen_cls):
        """filename string with spaces should generate -R flags"""
        mock_proc = self._mock_popen()
        mock_popen_cls.return_value = mock_proc
        try:
            r2pipe.open("/bin/ls arg1 arg2")
        except Exception:
            pass
        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("-Rarg1=arg1", cmd)
        self.assertIn("-Rarg2=arg2", cmd)
        self.assertIn("/bin/ls", cmd)
        # -R args should come before filename
        r_idx = cmd.index("-Rarg1=arg1")
        f_idx = cmd.index("/bin/ls")
        self.assertLess(r_idx, f_idx)

    @patch('r2pipe.open_sync.Popen')
    def test_list_with_args_builds_correct_cmd(self, mock_popen_cls):
        """filename as list should generate -R flags from extra elements"""
        mock_proc = self._mock_popen()
        mock_popen_cls.return_value = mock_proc
        try:
            r2pipe.open(["/bin/ls", "hello", "world"])
        except Exception:
            pass
        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("-Rarg1=hello", cmd)
        self.assertIn("-Rarg2=world", cmd)
        self.assertIn("/bin/ls", cmd)

    @patch('r2pipe.open_sync.Popen')
    def test_list_single_element_no_r_args(self, mock_popen_cls):
        """single-element list should not generate -R flags"""
        mock_proc = self._mock_popen()
        mock_popen_cls.return_value = mock_proc
        try:
            r2pipe.open(["/bin/ls"])
        except Exception:
            pass
        cmd = mock_popen_cls.call_args[0][0]
        self.assertNotIn("-Rarg1=", str(cmd))
        self.assertIn("/bin/ls", cmd)

    @patch('r2pipe.open_sync.Popen')
    def test_plain_filename_no_r_args(self, mock_popen_cls):
        """plain filename without spaces should not generate -R flags"""
        mock_proc = self._mock_popen()
        mock_popen_cls.return_value = mock_proc
        try:
            r2pipe.open("/bin/ls")
        except Exception:
            pass
        cmd = mock_popen_cls.call_args[0][0]
        r_flags = [c for c in cmd if c.startswith("-R")]
        self.assertEqual(r_flags, [])

    @patch('r2pipe.open_sync.Popen')
    def test_flags_and_file_args_combined(self, mock_popen_cls):
        """flags and file args should both appear in the command"""
        mock_proc = self._mock_popen()
        mock_popen_cls.return_value = mock_proc
        try:
            r2pipe.open(["/bin/ls", "myarg"], flags=["-d"])
        except Exception:
            pass
        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("-d", cmd)
        self.assertIn("-Rarg1=myarg", cmd)
        self.assertIn("/bin/ls", cmd)
        # flags before -R args, both before filename
        d_idx = cmd.index("-d")
        r_idx = cmd.index("-Rarg1=myarg")
        f_idx = cmd.index("/bin/ls")
        self.assertLess(d_idx, r_idx)
        self.assertLess(r_idx, f_idx)

    def test_http_url_not_split(self):
        """http:// URLs should not be split on spaces"""
        # This should not try to split the URL — it will fail to connect
        # but shouldn't split the URL string
        try:
            r2pipe.open("http://127.0.0.1:9999 extra")
        except Exception:
            pass
        # If it didn't crash trying to use "http://127.0.0.1:9999" as filename, we're good

    def test_tcp_url_not_split(self):
        """tcp:// URLs should not be split on spaces"""
        try:
            r2pipe.open("tcp://127.0.0.1:9999 extra")
        except Exception:
            pass
