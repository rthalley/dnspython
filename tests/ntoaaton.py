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
import dns.ipv6

class NtoAAtoNTestCase(unittest.TestCase):

    def test_aton1(self):
        a = dns.ipv6.inet_aton('::')
        self.assertTrue(a == b'\x00' * 16)

    def test_aton2(self):
        a = dns.ipv6.inet_aton('::1')
        self.assertTrue(a == b'\x00' * 15 + b'\x01')

    def test_aton3(self):
        a = dns.ipv6.inet_aton('::10.0.0.1')
        self.assertTrue(a == b'\x00' * 12 + b'\x0a\x00\x00\x01')

    def test_aton4(self):
        a = dns.ipv6.inet_aton('abcd::dcba')
        self.assertTrue(a == b'\xab\xcd' + b'\x00' * 12 + b'\xdc\xba')

    def test_aton5(self):
        a = dns.ipv6.inet_aton('1:2:3:4:5:6:7:8')
        self.assertTrue(a == \
                        bytes.fromhex('00010002000300040005000600070008'))

    def test_bad_aton1(self):
        def bad():
            a = dns.ipv6.inet_aton('abcd:dcba')
        self.assertRaises(dns.exception.SyntaxError, bad)

    def test_bad_aton2(self):
        def bad():
            a = dns.ipv6.inet_aton('abcd::dcba::1')
        self.assertRaises(dns.exception.SyntaxError, bad)

    def test_bad_aton3(self):
        def bad():
            a = dns.ipv6.inet_aton('1:2:3:4:5:6:7:8:9')
        self.assertRaises(dns.exception.SyntaxError, bad)

    def test_aton1(self):
        a = dns.ipv6.inet_aton('::')
        self.assertTrue(a == b'\x00' * 16)

    def test_aton2(self):
        a = dns.ipv6.inet_aton('::1')
        self.assertTrue(a == b'\x00' * 15 + b'\x01')

    def test_aton3(self):
        a = dns.ipv6.inet_aton('::10.0.0.1')
        self.assertTrue(a == b'\x00' * 12 + b'\x0a\x00\x00\x01')

    def test_aton4(self):
        a = dns.ipv6.inet_aton('abcd::dcba')
        self.assertTrue(a == b'\xab\xcd' + b'\x00' * 12 + b'\xdc\xba')

    def test_ntoa1(self):
        b = bytes.fromhex('00010002000300040005000600070008')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '1:2:3:4:5:6:7:8')

    def test_ntoa2(self):
        b = b'\x00' * 16
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::')

    def test_ntoa3(self):
        b = b'\x00' * 15 + b'\x01'
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::1')

    def test_ntoa4(self):
        b = b'\x80' + b'\x00' * 15
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '8000::')

    def test_ntoa5(self):
        b = b'\x01\xcd' + b'\x00' * 12 + b'\x03\xef'
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '1cd::3ef')

    def test_ntoa6(self):
        b = bytes.fromhex('ffff00000000ffff000000000000ffff')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == 'ffff:0:0:ffff::ffff')

    def test_ntoa7(self):
        b = bytes.fromhex('00000000ffff000000000000ffffffff')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '0:0:ffff::ffff:ffff')

    def test_ntoa8(self):
        b = bytes.fromhex('ffff0000ffff00000000ffff00000000')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == 'ffff:0:ffff::ffff:0:0')

    def test_ntoa9(self):
        b = bytes.fromhex('0000000000000000000000000a000001')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::10.0.0.1')

    def test_ntoa10(self):
        b = bytes.fromhex('0000000000000000000000010a000001')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::1:a00:1')

    def test_ntoa11(self):
        b = bytes.fromhex('00000000000000000000ffff0a000001')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::ffff:10.0.0.1')

    def test_ntoa12(self):
        b = bytes.fromhex('000000000000000000000000ffffffff')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::255.255.255.255')

    def test_ntoa13(self):
        b = bytes.fromhex('00000000000000000000ffffffffffff')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::ffff:255.255.255.255')

    def test_ntoa14(self):
        b = bytes.fromhex('0000000000000000000000000001ffff')
        t = dns.ipv6.inet_ntoa(b)
        self.assertTrue(t == '::0.1.255.255')

    def test_bad_ntoa1(self):
        def bad():
            a = dns.ipv6.inet_ntoa('')
        self.assertRaises(ValueError, bad)

    def test_bad_ntoa2(self):
        def bad():
            a = dns.ipv6.inet_ntoa(b'\x00' * 17)
        self.assertRaises(ValueError, bad)

if __name__ == '__main__':
    unittest.main()
