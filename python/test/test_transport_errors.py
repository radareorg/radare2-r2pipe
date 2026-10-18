import threading
import unittest
from unittest.mock import Mock

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


if __name__ == "__main__":
    unittest.main()
