import threading
import unittest
from unittest.mock import Mock, patch

import r2pipe
from r2pipe.open_sync import open as sync_open


class TestSyncTransportErrors(unittest.TestCase):
    def setUp(self):
        self.r2 = sync_open.__new__(sync_open)
        self.r2.asyn = False
        self.r2._cmd = self.r2._cmd_process
        self.r2._cmd_lock = threading.Lock()
        self.r2.pending = b""
        self.r2.process = Mock()
        self.r2.process.poll.return_value = None

    def test_write_and_flush_failures_propagate_without_reading(self):
        for operation in ("write", "flush"):
            for error in (BrokenPipeError("closed"), ValueError("closed file"),
                          KeyboardInterrupt(), SystemExit()):
                with self.subTest(operation=operation, error=type(error).__name__):
                    self.r2.pending = b"pending"
                    method = getattr(self.r2.process.stdin, operation)
                    method.side_effect = error
                    with self.assertRaises(type(error)) as caught:
                        self.r2.cmd("ij")
                    self.assertIs(caught.exception, error)
                    self.assertEqual(self.r2.pending, b"pending")
                    self.r2.process.stdout.read.assert_not_called()
                    method.side_effect = None

    def test_read_errors_propagate_without_retrying(self):
        for error in (OSError("read failed"), ValueError("closed file"),
                      KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error).__name__):
                read = self.r2.process.stdout.read
                read.reset_mock()
                read.side_effect = [error, b"unexpected retry\x00"]
                with self.assertRaises(type(error)) as caught:
                    self.r2.cmd("ij")
                self.assertIs(caught.exception, error)
                read.assert_called_once()

    def test_eof_before_terminator_raises_without_retrying(self):
        for chunks in ([b""], [b"partial", b""]):
            with self.subTest(chunks=chunks):
                read = self.r2.process.stdout.read
                read.reset_mock()
                read.side_effect = chunks + [b"unexpected retry\x00"]
                with self.assertRaisesRegex(ConnectionError, "closed"):
                    self.r2.cmd("ij")
                self.assertEqual(read.call_count, len(chunks))

    def test_terminated_responses_still_succeed(self):
        for chunks, expected in (([b"\x00"], ""), ([b"hel", b"lo\x00"], "hello")):
            with self.subTest(chunks=chunks):
                self.r2.process.stdout.read.side_effect = chunks
                self.assertEqual(self.r2.cmd("ij"), expected)


class TestSessionDiscoveryErrors(unittest.TestCase):
    def test_interrupts_propagate(self):
        for error in (KeyboardInterrupt(), SystemExit()):
            with self.subTest(error=type(error).__name__):
                with patch("r2pipe.open_base.Popen") as popen:
                    popen.return_value.communicate.side_effect = error
                    with self.assertRaises(type(error)) as caught:
                        r2pipe.local_sessions()
                    self.assertIs(caught.exception, error)

    def test_unavailable_agent_still_returns_empty_list(self):
        with patch("r2pipe.open_base.Popen", side_effect=OSError("unavailable")):
            self.assertEqual(r2pipe.local_sessions(), [])

    def test_agent_responses(self):
        cases = ((0, b'[{"uri": "http://localhost:9090"}]',
                  [{"uri": "http://localhost:9090"}]),
                 (1, b"", []), (0, b"invalid JSON", []), (0, b"{}", []))
        for status, output, expected in cases:
            with self.subTest(status=status, output=output):
                with patch("r2pipe.open_base.Popen") as popen:
                    popen.return_value.returncode = status
                    popen.return_value.communicate.return_value = (output, b"")
                    self.assertEqual(r2pipe.local_sessions(), expected)


if __name__ == "__main__":
    unittest.main()
