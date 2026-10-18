"""Unsigned IO addresses remain exact for both wire representations."""
import json
import unittest
import r2pipe


class AddressTests(unittest.TestCase):
    def test_numeric_and_hexadecimal_addresses(self):
        for value in (0, 17, 2**53 - 1, 2**53 + 1, 2**63 + 1, 2**64 - 1):
            with self.subTest(value=value):
                self.assertEqual(r2pipe.parse_address(value), value)
                self.assertEqual(r2pipe.parse_address(hex(value)), value)
                self.assertEqual(r2pipe.parse_address(json.loads(str(value))), value)

    def test_invalid_addresses(self):
        for value in (True, None, {}, 1.5, -1, 2**64, "", "17", "0x", "-0x1",
                      "0x10000000000000000", "0x1junk"):
            with self.subTest(value=value):
                with self.assertRaises((TypeError, ValueError)):
                    r2pipe.parse_address(value)
