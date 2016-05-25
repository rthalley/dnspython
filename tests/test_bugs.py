# Copyright (C) 2006, 2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

from io import BytesIO
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.ttl

class BugsTestCase(unittest.TestCase):

    def test_float_LOC(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.LOC,
                                    u"30 30 0.000 N 100 30 0.000 W 10.00m 20m 2000m 20m")
        self.failUnless(rdata.float_latitude == 30.5)
        self.failUnless(rdata.float_longitude == -100.5)

    def test_SOA_BIND8_TTL(self):
        rdata1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA,
                                     u"a b 100 1s 1m 1h 1d")
        rdata2 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA,
                                     u"a b 100 1 60 3600 86400")
        self.failUnless(rdata1 == rdata2)

    def test_TTL_bounds_check(self):
        def bad():
            ttl = dns.ttl.from_text("2147483648")
        self.failUnlessRaises(dns.ttl.BadTTL, bad)

    def test_empty_NSEC3_window(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3,
                                    u"1 0 100 ABCD SCBCQHKU35969L2A68P3AD59LHF30715")
        self.failUnless(rdata.windows == [])

    def test_zero_size_APL(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.APL,
                                    "")
        rdata2 = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.APL,
                                     "", 0, 0)
        self.failUnless(rdata == rdata2)

    def test_CAA_from_wire(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CAA,
                                    u'0 issue "ca.example.net"');
        f = BytesIO()
        rdata.to_wire(f)
        wire = f.getvalue()
        rdlen = len(wire)
        wire += b"trailing garbage"
        rdata2 = dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.CAA,
                                     wire, 0, rdlen)
        self.failUnless(rdata == rdata2)

if __name__ == '__main__':
    unittest.main()
