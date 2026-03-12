import ctypes
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

import r2pipe
from r2pipe.native import *
from r2pipe.open_async import open as async_open


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
        os.system("sh race.sh")

    def test_native_rcore(self):
        c = RCore()
        value = c.cmd_str("o %s/ls; s entry0;pi 1 @e:scr.color=0" % self.curdir).strip()
        c.free()
        self.assertEqual(value, "push rbp")


class TestFilenameArgsParsing(unittest.TestCase):
    """Test that filename arguments are correctly parsed into -R flags (PR #91)."""

    def _mock_popen(self):
        """Create a mock Popen that captures the command and simulates r2."""
        mock_proc = MagicMock()
        mock_proc.stdout.read.return_value = b"\x00"
        mock_proc.stdin.write.return_value = None
        mock_proc.stdin.flush.return_value = None
        mock_proc.poll.return_value = None
        return mock_proc

    @patch("r2pipe.open_sync.Popen")
    def test_string_with_args_builds_correct_cmd(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        r2pipe.open("/bin/ls arg1 arg2")

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("-Rarg1=arg1", cmd)
        self.assertIn("-Rarg2=arg2", cmd)
        self.assertIn("/bin/ls", cmd)
        self.assertLess(cmd.index("-Rarg1=arg1"), cmd.index("/bin/ls"))

    @patch("r2pipe.open_sync.Popen")
    def test_list_with_args_builds_correct_cmd(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        r2pipe.open(["/bin/ls", "hello", "world"])

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("-Rarg1=hello", cmd)
        self.assertIn("-Rarg2=world", cmd)
        self.assertIn("/bin/ls", cmd)

    @patch("r2pipe.open_sync.Popen")
    def test_list_single_element_no_r_args(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        r2pipe.open(["/bin/ls"])

        cmd = mock_popen_cls.call_args[0][0]
        self.assertNotIn("-Rarg1=", str(cmd))
        self.assertIn("/bin/ls", cmd)

    @patch("r2pipe.open_sync.Popen")
    def test_plain_filename_no_r_args(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        r2pipe.open("/bin/ls")

        cmd = mock_popen_cls.call_args[0][0]
        r_flags = [part for part in cmd if part.startswith("-R")]
        self.assertEqual(r_flags, [])

    @patch("r2pipe.open_sync.Popen")
    def test_flags_and_file_args_combined(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        r2pipe.open(["/bin/ls", "myarg"], flags=["-d"])

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn("-d", cmd)
        self.assertIn("-Rarg1=myarg", cmd)
        self.assertIn("/bin/ls", cmd)
        self.assertLess(cmd.index("-d"), cmd.index("-Rarg1=myarg"))
        self.assertLess(cmd.index("-Rarg1=myarg"), cmd.index("/bin/ls"))

    @patch("r2pipe.open_sync.Popen")
    def test_pathlike_filename_is_accepted(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        filename = Path("/tmp/test-bin")
        r2pipe.open(filename)

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn(os.fspath(filename), cmd)
        r_flags = [part for part in cmd if part.startswith("-R")]
        self.assertEqual(r_flags, [])

    @patch("r2pipe.open_sync.Popen")
    def test_pathlike_filename_with_spaces_is_not_split(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        filename = Path("/tmp/path with spaces/test-bin")
        r2pipe.open(filename)

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn(os.fspath(filename), cmd)
        r_flags = [part for part in cmd if part.startswith("-R")]
        self.assertEqual(r_flags, [])

    @patch("r2pipe.open_sync.Popen")
    def test_pathlike_list_filename_and_args_are_coerced(self, mock_popen_cls):
        mock_popen_cls.return_value = self._mock_popen()

        filename = Path("/tmp/test-bin")
        arg = Path("relative-arg")
        r2pipe.open([filename, arg])

        cmd = mock_popen_cls.call_args[0][0]
        self.assertIn(os.fspath(filename), cmd)
        self.assertIn(f"-Rarg1={os.fspath(arg)}", cmd)

    @patch("r2pipe.open_sync.Popen")
    def test_http_url_not_split(self, mock_popen_cls):
        r2 = r2pipe.open("http://127.0.0.1:9999 extra")

        self.assertEqual(r2.uri, "http://127.0.0.1:9999 extra/cmd")
        mock_popen_cls.assert_not_called()

    @patch("r2pipe.open_sync.Popen")
    @patch("r2pipe.open_sync.socket.socket")
    def test_tcp_url_not_split(self, mock_socket_cls, mock_popen_cls):
        mock_conn = MagicMock()
        mock_socket_cls.return_value = mock_conn

        r2 = r2pipe.open("tcp://127.0.0.1:9999 extra")

        self.assertIs(r2.conn, mock_conn)
        mock_conn.connect.assert_called_once_with(("127.0.0.1", 9999))
        mock_popen_cls.assert_not_called()

    def test_async_pathlike_filename_is_accepted(self):
        filename = Path("/tmp/test-bin")
        r2 = async_open(filename)

        self.assertEqual(r2._process_start_cmd[-1], os.fspath(filename))
        self.assertEqual([part for part in r2._process_start_cmd if part.startswith("-R")], [])
        r2.close()

    def test_async_pathlike_filename_with_spaces_is_not_split(self):
        filename = Path("/tmp/path with spaces/test-bin")
        r2 = async_open(filename)

        self.assertEqual(r2._process_start_cmd[-1], os.fspath(filename))
        self.assertEqual([part for part in r2._process_start_cmd if part.startswith("-R")], [])
        r2.close()
