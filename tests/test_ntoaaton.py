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

import dns.exception
import dns.ipv4
import dns.ipv6

# for convenience
aton4 = dns.ipv4.inet_aton
ntoa4 = dns.ipv4.inet_ntoa
aton6 = dns.ipv6.inet_aton
ntoa6 = dns.ipv6.inet_ntoa

v4_bad_addrs = ['256.1.1.1', '1.1.1', '1.1.1.1.1', '01.1.1.1',
                '+1.1.1.1', '1.1.1.1+', '1..2.3.4', '.1.2.3.4',
                '1.2.3.4.']

class NtoAAtoNTestCase(unittest.TestCase):

    def test_aton1(self):
        a = aton6('::')
        self.failUnless(a == '\x00' * 16)

    def test_aton2(self):
        a = aton6('::1')
        self.failUnless(a == '\x00' * 15 + '\x01')

    def test_aton3(self):
        a = aton6('::10.0.0.1')
        self.failUnless(a == '\x00' * 12 + '\x0a\x00\x00\x01')

    def test_aton4(self):
        a = aton6('abcd::dcba')
        self.failUnless(a == '\xab\xcd' + '\x00' * 12 + '\xdc\xba')

    def test_aton5(self):
        a = aton6('1:2:3:4:5:6:7:8')
        self.failUnless(a == \
                        '00010002000300040005000600070008'.decode('hex_codec'))

    def test_bad_aton1(self):
        def bad():
            a = aton6('abcd:dcba')
        self.failUnlessRaises(dns.exception.SyntaxError, bad)

    def test_bad_aton2(self):
        def bad():
            a = aton6('abcd::dcba::1')
        self.failUnlessRaises(dns.exception.SyntaxError, bad)

    def test_bad_aton3(self):
        def bad():
            a = aton6('1:2:3:4:5:6:7:8:9')
        self.failUnlessRaises(dns.exception.SyntaxError, bad)

    def test_aton1(self):
        a = aton6('::')
        self.failUnless(a == '\x00' * 16)

    def test_aton2(self):
        a = aton6('::1')
        self.failUnless(a == '\x00' * 15 + '\x01')

    def test_aton3(self):
        a = aton6('::10.0.0.1')
        self.failUnless(a == '\x00' * 12 + '\x0a\x00\x00\x01')

    def test_aton4(self):
        a = aton6('abcd::dcba')
        self.failUnless(a == '\xab\xcd' + '\x00' * 12 + '\xdc\xba')

    def test_ntoa1(self):
        b = '00010002000300040005000600070008'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '1:2:3:4:5:6:7:8')

    def test_ntoa2(self):
        b = '\x00' * 16
        t = ntoa6(b)
        self.failUnless(t == '::')

    def test_ntoa3(self):
        b = '\x00' * 15 + '\x01'
        t = ntoa6(b)
        self.failUnless(t == '::1')

    def test_ntoa4(self):
        b = '\x80' + '\x00' * 15
        t = ntoa6(b)
        self.failUnless(t == '8000::')

    def test_ntoa5(self):
        b = '\x01\xcd' + '\x00' * 12 + '\x03\xef'
        t = ntoa6(b)
        self.failUnless(t == '1cd::3ef')

    def test_ntoa6(self):
        b = 'ffff00000000ffff000000000000ffff'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == 'ffff:0:0:ffff::ffff')

    def test_ntoa7(self):
        b = '00000000ffff000000000000ffffffff'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '0:0:ffff::ffff:ffff')

    def test_ntoa8(self):
        b = 'ffff0000ffff00000000ffff00000000'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == 'ffff:0:ffff::ffff:0:0')

    def test_ntoa9(self):
        b = '0000000000000000000000000a000001'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '::10.0.0.1')

    def test_ntoa10(self):
        b = '0000000000000000000000010a000001'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '::1:a00:1')

    def test_ntoa11(self):
        b = '00000000000000000000ffff0a000001'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '::ffff:10.0.0.1')

    def test_ntoa12(self):
        b = '000000000000000000000000ffffffff'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '::255.255.255.255')

    def test_ntoa13(self):
        b = '00000000000000000000ffffffffffff'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '::ffff:255.255.255.255')

    def test_ntoa14(self):
        b = '0000000000000000000000000001ffff'.decode('hex_codec')
        t = ntoa6(b)
        self.failUnless(t == '::0.1.255.255')

    def test_bad_ntoa1(self):
        def bad():
            a = ntoa6('')
        self.failUnlessRaises(ValueError, bad)

    def test_bad_ntoa2(self):
        def bad():
            a = ntoa6('\x00' * 17)
        self.failUnlessRaises(ValueError, bad)

    def test_good_v4_aton(self):
        pairs = [('1.2.3.4', '\x01\x02\x03\x04'),
                 ('255.255.255.255', '\xff\xff\xff\xff'),
                 ('0.0.0.0', '\x00\x00\x00\x00')]
        for (t, b) in pairs:
            b1 = aton4(t)
            t1 = ntoa4(b1)
            self.failUnless(b1 == b)
            self.failUnless(t1 == t)

    def test_bad_v4_aton(self):
        def make_bad(a):
            def bad():
                return aton4(a)
            return bad
        for addr in v4_bad_addrs:
            self.failUnlessRaises(dns.exception.SyntaxError, make_bad(addr))

    def test_bad_v6_aton(self):
        addrs = ['+::0', '0::0::', '::0::', '1:2:3:4:5:6:7:8:9',
                 ':::::::']
        embedded = ['::' + x for x in v4_bad_addrs]
        addrs.extend(embedded)
        def make_bad(a):
            def bad():
                x = aton6(a)
            return bad
        for addr in addrs:
            self.failUnlessRaises(dns.exception.SyntaxError, make_bad(addr))

    def test_rfc5952_section_4_2_2(self):
        addr = '2001:db8:0:1:1:1:1:1'
        b1 = aton6(addr)
        t1 = ntoa6(b1)
        self.failUnless(t1 == addr)

    def test_is_mapped(self):
        t1 = '2001:db8:0:1:1:1:1:1'
        t2 = '::ffff:127.0.0.1'
        t3 = '1::ffff:127.0.0.1'
        self.failIf(dns.ipv6.is_mapped(aton6(t1)))
        self.failUnless(dns.ipv6.is_mapped(aton6(t2)))
        self.failIf(dns.ipv6.is_mapped(aton6(t3)))

if __name__ == '__main__':
    unittest.main()
