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

try:
    import unittest2 as unittest
except ImportError:
    import unittest

import dns.rdata
import dns.rdataclass
import dns.rdatatype

class RdataTestCase(unittest.TestCase):

    def test_str(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        self.failUnless(rdata.address == "1.2.3.4")

    def test_unicode(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, u"1.2.3.4")
        self.failUnless(rdata.address == "1.2.3.4")

if __name__ == '__main__':
    unittest.main()
