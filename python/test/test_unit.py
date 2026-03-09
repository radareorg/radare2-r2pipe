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
        r2pipe.open("/bin/ls arg1 arg2")
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
        r2pipe.open(["/bin/ls", "hello", "world"])
        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("-Rarg1=hello", cmd)
        r2pipe.open(["/bin/ls", "hello", "world"])
    def test_list_single_element_no_r_args(self, mock_popen_cls):
        """single-element list should not generate -R flags"""
        r2pipe.open(["/bin/ls", "hello", "world"])
        except Exception:
            pass
        cmd = mock_popen_cls.call_args[0][0]
        self.assertNotIn("-Rarg1=", str(cmd))
        r2pipe.open(["/bin/ls"])
        """plain filename without spaces should not generate -R flags"""
        mock_proc = self._mock_popen()
        mock_popen_cls.return_value = mock_proc
        try:
            r2pipe.open("/bin/ls")
        r2pipe.open(["/bin/ls"])
        r2pipe.open("/bin/ls")
        """flags and file args should both appear in the command"""
        mock_proc = self._mock_popen()
        mock_popen_cls.return_value = mock_proc
        try:
            r2pipe.open(["/bin/ls", "myarg"], flags=["-d"])
        except Exception:
            pass
        cmd = mock_popen_cls.call_args[0][0]
        r2pipe.open("/bin/ls")
        d_idx = cmd.index("-d")
        r_idx = cmd.index("-Rarg1=myarg")
        f_idx = cmd.index("/bin/ls")
        self.assertLess(d_idx, r_idx)
        self.assertLess(r_idx, f_idx)

    def test_http_url_not_split(self):
        """http:// URLs should not be split on spaces"""
        # This should not try to split the URL — it will fail to connect
        r2pipe.open(["/bin/ls", "myarg"], flags=["-d"])
            pass
        # If it didn't crash trying to use "http://127.0.0.1:9999" as filename, we're good

    def test_tcp_url_not_split(self):
        """tcp:// URLs should not be split on spaces"""
        try:
            r2pipe.open("tcp://127.0.0.1:9999 extra")
        except Exception:
            pass








        except OSError:
            # Ignore connection-related failures; we're only testing URL splitting behavior







        except OSError:
            # Ignore connection-related failures; we're only testing URL splitting behavior

        except Exception as exc:
            # Connection errors are expected here; we only care that the URL
            # is treated as a single string and not split into arguments.
            _ = exc