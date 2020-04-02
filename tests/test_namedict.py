# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
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

import dns.name
import dns.namedict

class NameTestCase(unittest.TestCase):

    def setUp(self):
        self.ndict = dns.namedict.NameDict()
        n1 = dns.name.from_text('foo.bar.')
        n2 = dns.name.from_text('bar.')
        self.ndict[n1] = 1
        self.ndict[n2] = 2
        self.rndict = dns.namedict.NameDict()
        n1 = dns.name.from_text('foo.bar', None)
        n2 = dns.name.from_text('bar', None)
        self.rndict[n1] = 1
        self.rndict[n2] = 2

    def testDepth(self):
        self.assertEqual(self.ndict.max_depth, 3)

    def testLookup1(self):
        k = dns.name.from_text('foo.bar.')
        self.assertEqual(self.ndict[k], 1)

    def testLookup2(self):
        k = dns.name.from_text('foo.bar.')
        self.assertEqual(self.ndict.get_deepest_match(k)[1], 1)

    def testLookup3(self):
        k = dns.name.from_text('a.b.c.foo.bar.')
        self.assertEqual(self.ndict.get_deepest_match(k)[1], 1)

    def testLookup4(self):
        k = dns.name.from_text('a.b.c.bar.')
        self.assertEqual(self.ndict.get_deepest_match(k)[1], 2)

    def testLookup5(self):
        def bad():
            n = dns.name.from_text('a.b.c.')
            self.ndict.get_deepest_match(n)
        self.assertRaises(KeyError, bad)

    def testLookup6(self):
        def bad():
            self.ndict.get_deepest_match(dns.name.empty)
        self.assertRaises(KeyError, bad)

    def testLookup7(self):
        self.ndict[dns.name.empty] = 100
        n = dns.name.from_text('a.b.c.')
        v = self.ndict.get_deepest_match(n)[1]
        self.assertEqual(v, 100)

    def testLookup8(self):
        def bad():
            self.ndict['foo'] = 100
        self.assertRaises(ValueError, bad)

    def testRelDepth(self):
        self.assertEqual(self.rndict.max_depth, 2)

    def testRelLookup1(self):
        k = dns.name.from_text('foo.bar', None)
        self.assertEqual(self.rndict[k], 1)

    def testRelLookup2(self):
        k = dns.name.from_text('foo.bar', None)
        self.assertEqual(self.rndict.get_deepest_match(k)[1], 1)

    def testRelLookup3(self):
        k = dns.name.from_text('a.b.c.foo.bar', None)
        self.assertEqual(self.rndict.get_deepest_match(k)[1], 1)

    def testRelLookup4(self):
        k = dns.name.from_text('a.b.c.bar', None)
        self.assertEqual(self.rndict.get_deepest_match(k)[1], 2)

    def testRelLookup7(self):
        self.rndict[dns.name.empty] = 100
        n = dns.name.from_text('a.b.c', None)
        v = self.rndict.get_deepest_match(n)[1]
        self.assertEqual(v, 100)

if __name__ == '__main__':
    unittest.main()
