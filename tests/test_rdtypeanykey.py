# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

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


if __name__ == "__main__":
    unittest.main()
