
import unittest

import dns.exception
import dns.wire
import dns.name


class BinaryTestCase(unittest.TestCase):

    def test_basic(self):
        wire = bytes.fromhex('0102010203040102')
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_uint16(), 0x0102)
        with p.restrict_to(5):
            self.assertEqual(p.get_uint32(), 0x01020304)
            self.assertEqual(p.get_uint8(), 0x01)
            self.assertEqual(p.remaining(), 0)
            with self.assertRaises(dns.exception.FormError):
                p.get_uint16()
        self.assertEqual(p.remaining(), 1)
        self.assertEqual(p.get_uint8(), 0x02)
        with self.assertRaises(dns.exception.FormError):
            p.get_uint8()

    def test_name(self):
        # www.dnspython.org NS IN question
        wire = b'\x03www\x09dnspython\x03org\x00\x00\x02\x00\x01'
        expected = dns.name.from_text('www.dnspython.org')
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_name(), expected)
        self.assertEqual(p.get_uint16(), 2)
        self.assertEqual(p.get_uint16(), 1)
        self.assertEqual(p.remaining(), 0)

    def test_relativized_name(self):
        # www.dnspython.org NS IN question
        wire = b'\x03www\x09dnspython\x03org\x00\x00\x02\x00\x01'
        origin = dns.name.from_text('dnspython.org')
        expected = dns.name.from_text('www', None)
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_name(origin), expected)
        self.assertEqual(p.remaining(), 4)

    def test_compressed_name(self):
        # www.dnspython.org NS IN question
        wire = b'\x09dnspython\x03org\x00\x03www\xc0\x00'
        expected1 = dns.name.from_text('dnspython.org')
        expected2 = dns.name.from_text('www.dnspython.org')
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_name(), expected1)
        self.assertEqual(p.get_name(), expected2)
        self.assertEqual(p.remaining(), 0)
        # verify the unseek()
        self.assertEqual(p.current, len(wire))
