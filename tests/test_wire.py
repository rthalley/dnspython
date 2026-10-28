# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import io
import unittest

import dns.exception
import dns.wire
import dns.name
import dns.rdata
import dns._render_util


class BinaryTestCase(unittest.TestCase):
    def test_basic(self):
        wire = bytes.fromhex("0102010203040102")
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
        wire = b"\x03www\x09dnspython\x03org\x00\x00\x02\x00\x01"
        expected = dns.name.from_text("www.dnspython.org")
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_name(), expected)
        self.assertEqual(p.get_uint16(), 2)
        self.assertEqual(p.get_uint16(), 1)
        self.assertEqual(p.remaining(), 0)

    def test_relativized_name(self):
        # www.dnspython.org NS IN question
        wire = b"\x03www\x09dnspython\x03org\x00\x00\x02\x00\x01"
        origin = dns.name.from_text("dnspython.org")
        expected = dns.name.from_text("www", None)
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_name(origin), expected)
        self.assertEqual(p.remaining(), 4)

    def test_compressed_name(self):
        # www.dnspython.org NS IN question
        wire = b"\x09dnspython\x03org\x00\x03www\xc0\x00"
        expected1 = dns.name.from_text("dnspython.org")
        expected2 = dns.name.from_text("www.dnspython.org")
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_name(decompress=True), expected1)
        self.assertEqual(p.get_name(decompress=True), expected2)
        self.assertEqual(p.remaining(), 0)
        # verify the restore_furthest()
        self.assertEqual(p.current, len(wire))
        # If compression is disallowed, we should fail on the second
        # name.
        p = dns.wire.Parser(wire)
        self.assertEqual(p.get_name(decompress=True), expected1)
        with self.assertRaises(dns.name.DecompressionForbidden):
            p.get_name(decompress=False)

    def test_seek(self):
        wire = b"\x09dnspython\x03org\x00"
        p = dns.wire.Parser(wire)
        p.seek(10)
        self.assertEqual(p.get_uint8(), 3)
        # seeking to the end index is OK
        p.seek(len(wire))
        self.assertEqual(p.current, p.end)
        with self.assertRaises(dns.exception.FormError):
            # but reading there will not succeed
            p.get_uint8()
        with self.assertRaises(dns.exception.FormError):
            p.seek(-1)
        with self.assertRaises(dns.exception.FormError):
            p.seek(len(wire) + 1)

    def test_not_reading_everything_in_restriction(self):
        wire = bytes.fromhex("0102010203040102")
        p = dns.wire.Parser(wire)
        with self.assertRaises(dns.exception.FormError):
            with p.restrict_to(5):
                v = p.get_uint8()
                self.assertEqual(v, 1)
                # don't read the other 4 bytes

    def test_restriction_does_not_mask_exception(self):
        wire = bytes.fromhex("0102010203040102")
        p = dns.wire.Parser(wire)
        with self.assertRaises(NotImplementedError):
            with p.restrict_to(5):
                raise NotImplementedError

    def test_prefixed_length(self):
        out = io.BytesIO()
        with dns._render_util.prefixed_length(out, 1):
            out.write(b"hello")
        value = out.getvalue()
        self.assertEqual(value, b"\x05hello")

    def test_prefixed_length_overflow(self):
        out = io.BytesIO()
        with self.assertRaises(dns.exception.FormError):
            with dns._render_util.prefixed_length(out, 1):
                out.write(b"x" * 256)

    def test_rdata_decompression_policy(self):
        # NSBase
        a_name = dns.name.from_text("a.foo.")
        wire = b"\x03foo\x00\x01a\xc0\x00"
        rdata = dns.rdata.from_wire("IN", "CNAME", wire, 5, 4)
        self.assertEqual(rdata.target, a_name)
        # UncompressedNS
        with self.assertRaises(dns.name.DecompressionForbidden):
            dns.rdata.from_wire("IN", "DNAME", wire, 5, 4)
        # MXBase
        wire = b"\x03foo\x00\x00\x0a\x01a\xc0\x00"
        rdata = dns.rdata.from_wire("IN", "MX", wire, 5, 6)
        self.assertEqual(rdata.preference, 10)
        self.assertEqual(rdata.exchange, a_name)
        # DecompressionOnlyDowncasingMX
        rdata = dns.rdata.from_wire("IN", "AFSDB", wire, 5, 6)
        self.assertEqual(rdata.subtype, 10)
        self.assertEqual(rdata.hostname, a_name)
        # UncompressedDowncasingMX
        with self.assertRaises(dns.name.DecompressionForbidden):
            dns.rdata.from_wire("IN", "KX", wire, 5, 6)
        # UncompressedMX -- none currently, but here is where to test it
        #
        # SOA
        wire = b"\x03foo\x00\x01a\xc0\x00\x01a\xc0\x00" + b"\x00" * 20
        rdata = dns.rdata.from_wire("IN", "SOA", wire, 5, 28)
        self.assertEqual(rdata.mname, a_name)
        # SRV
        wire = b"\x03foo\x00\x00\x00\x00\x00\x00\x00\x01a\xc0\x00"
        rdata = dns.rdata.from_wire("IN", "SRV", wire, 5, 10)
        self.assertEqual(rdata.target, a_name)
        # NAPTR
        wire = b"\x03foo\x00\x00\x00\x00\x00\x00\x00\x00\x01a\xc0\x00"
        rdata = dns.rdata.from_wire("IN", "NAPTR", wire, 5, 11)
        self.assertEqual(rdata.replacement, a_name)
        # RP
        wire = b"\x03foo\x00\x01a\xc0\x00\x01a\xc0\x00"
        rdata = dns.rdata.from_wire("IN", "RP", wire, 5, 8)
        self.assertEqual(rdata.mbox, a_name)
        # PX
        wire = b"\x03foo\x00\x00\x00\x01a\xc0\x00\x01a\xc0\x00"
        rdata = dns.rdata.from_wire("IN", "PX", wire, 5, 10)
        self.assertEqual(rdata.mapx400, a_name)
        # SIG -- too annoying to test it!
        #
        # DSYNC -- chosen as an example of a type where there is no compression or
        # decompression, and the default behavior of Parser.get_name() is used.
        wire = b"\x03foo\x00\x00\x00\x01\x00\x00\x01a\xc0\x00"
        with self.assertRaises(dns.name.DecompressionForbidden):
            dns.rdata.from_wire("IN", "DSYNC", wire, 5, 9)

