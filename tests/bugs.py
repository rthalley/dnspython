# Copyright (C) 2005 Nominum, Inc.
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

import unittest

import dns.rdata
import dns.rdataclass
import dns.rdatatype

class BugsTestCase(unittest.TestCase):

    def test_float_LOC(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.LOC,
                                    "30 30 0.000 N 100 30 0.000 W 10.00m 20m 2000m 20m")
        self.failUnless(rdata.float_latitude == 30.5)
        self.failUnless(rdata.float_longitude == -100.5)

if __name__ == '__main__':
    unittest.main()
