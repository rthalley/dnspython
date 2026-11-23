# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.KEY
import dns.rrset


class RdtypeAnyKeyTestCase(unittest.TestCase):
    def testFlagsRRToText(self):  # type: () -> None
        """Test that RR method returns correct flags."""

        rr = dns.rrset.from_text("foo", 300, "IN", "KEY", "HOST 3 8 KEY=")[0]
        self.assertEqual(rr.flags, 512)

        rr = dns.rrset.from_text("foo", 300, "IN", "KEY", "257 3 8 KEY=")[0]
        self.assertEqual(rr.flags, 257)

        rr = dns.rrset.from_text("foo", 300, "IN", "KEY", "ZONE|SIG1 3 8 KEY=")[0]
        self.assertEqual(rr.flags, 257)

        with self.assertRaises(dns.exception.SyntaxError):
            _ = dns.rrset.from_text("foo", 300, "IN", "KEY", "ZONE|XYZZY 3 8 KEY=")[0]

        rr = dns.rrset.from_text("foo", 300, "IN", "KEY", "NOKEY 3 8")[0]
        self.assertEqual(rr.flags, 49152)
        self.assertEqual(rr.protocol, 3)
        self.assertEqual(rr.algorithm, 8)
        self.assertEqual(rr.key, b"")

    def testAlgorithmRRToText(self):  # type: () -> None
        """Test that RR method returns correct flags."""

        rr = dns.rrset.from_text("foo", 300, "IN", "KEY", "257 DNSSEC 8 KEY=")[0]
        self.assertEqual(rr.protocol, 3)

        rr = dns.rrset.from_text("foo", 300, "IN", "KEY", "257 IPSEC 8 KEY=")[0]
        self.assertEqual(rr.protocol, 4)

        with self.assertRaises(dns.exception.SyntaxError):
            _ = dns.rrset.from_text("foo", 300, "IN", "KEY", "257 XYZZY 8 KEY=")[0]

    def testKeyPresenceMatchesTypeFlags(self):  # type: () -> None
        """A NOKEY KEY has no key, and any other KEY has one (RFC 2535 3.1.2)."""

        def from_wire(wire):
            return dns.rdata.from_wire(
                dns.rdataclass.IN, dns.rdatatype.KEY, wire, 0, len(wire)
            )

        # The text form could not read back what to_text() wrote for these.
        for wire in (
            bytes.fromhex("c0000308") + b"\x01\x02\x03\x04",  # NOKEY with a key
            bytes.fromhex("01000308"),  # ZONE without a key
        ):
            with self.assertRaises(dns.exception.FormError):
                from_wire(wire)
        with self.assertRaises(ValueError):
            dns.rdtypes.ANY.KEY.KEY(
                dns.rdataclass.IN, dns.rdatatype.KEY, 0xC000, 3, 8, b"\x01"
            )
        with self.assertRaises(ValueError):
            dns.rdtypes.ANY.KEY.KEY(dns.rdataclass.IN, dns.rdatatype.KEY, 0, 3, 8, b"")
        with self.assertRaises(dns.exception.SyntaxError):
            dns.rrset.from_text("foo", 300, "IN", "KEY", "NOKEY 3 8 KEY=")
        with self.assertRaises(dns.exception.SyntaxError):
            dns.rrset.from_text("foo", 300, "IN", "KEY", "ZONE 3 8")
        # Consistent records still round trip over the wire and the text.
        for wire in (bytes.fromhex("c0000308"), bytes.fromhex("01000308") + b"\x01"):
            rd = from_wire(wire)
            self.assertEqual(rd.to_wire(), wire)
            self.assertEqual(
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.KEY, rd.to_text()),
                rd,
            )


if __name__ == "__main__":
    unittest.main()
