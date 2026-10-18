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


if __name__ == "__main__":
    unittest.main()
