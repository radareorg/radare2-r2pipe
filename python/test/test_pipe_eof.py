import os
import unittest
from unittest.mock import patch

from r2pipe.open_base import OpenBase


@unittest.skipIf(os.name == "nt", "Tests the POSIX embedded pipe reader")
class TestPipeEOF(unittest.TestCase):
    def setUp(self):
        self.r2 = OpenBase.__new__(OpenBase)
        self.r2.pipe = [123, 124]
        self.r2.use_cache = True
        self.r2.cache = {}
        self.r2._cmd = self.r2._cmd_pipe

    def test_eof_before_terminator_raises_without_reading_again(self):
        responses = [
            [b""],
            [b"partial response", b""],
            [b"x" * 4096, b"last fragment", b""],
        ]
        for chunks in responses:
            with self.subTest(chunks=[len(chunk) for chunk in chunks]):
                with patch("r2pipe.open_base.os.write"), patch(
                    "r2pipe.open_base.os.read",
                    side_effect=chunks + [AssertionError("Read again after EOF")],
                ) as read:
                    with self.assertRaisesRegex(ConnectionError, "closed"):
                        self.r2.cmd("?e hello")
                    self.assertEqual(read.call_count, len(chunks))
                self.assertNotIn("?e hello", self.r2.cache)

    def test_empty_terminated_response_succeeds(self):
        with patch("r2pipe.open_base.os.write"), patch(
            "r2pipe.open_base.os.read", return_value=b"\x00"
        ):
            self.assertEqual(self.r2.cmd("?e hello"), "")
        self.assertEqual(self.r2.cache["?e hello"], "")

    def test_fragmented_terminated_response_succeeds_and_is_cached(self):
        with patch("r2pipe.open_base.os.write") as write, patch(
            "r2pipe.open_base.os.read",
            side_effect=[b"caf\xc3", b"\xa9\n", b"\x00"],
        ) as read:
            self.assertEqual(self.r2.cmd("?e hello"), "café\n")
            self.assertEqual(self.r2.cmd("?e hello"), "café\n")
            self.assertEqual(read.call_count, 3)
            write.assert_called_once()


if __name__ == "__main__":
    unittest.main()
