# Copyright (C) 2014 Red Hat, Inc.
# Author: Petr Spacek <pspacek@redhat.com>
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED 'AS IS' AND RED HAT DISCLAIMS ALL WARRANTIES
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

import dns.rrset
import dns.rdtypes.ANY.DNSKEY


class RdtypeAnyDnskeyTestCase(unittest.TestCase):

    def testFlagsEmpty(self):
        '''Test DNSKEY flag to/from text conversion for zero flag/empty set.'''
        good_s = set()
        good_f = 0
        from_flags = dns.rdtypes.ANY.DNSKEY.flags_to_text_set(good_f)
        self.failUnless(from_flags == good_s,
                        '"%s" != "%s"' % (from_flags, good_s))
        from_set = dns.rdtypes.ANY.DNSKEY.flags_from_text_set(good_s)
        self.failUnless(from_set == good_f,
                        '"0x%x" != "0x%x"' % (from_set, good_f))

    def testFlagsAll(self):
        '''Test that all defined flags are recognized.'''
        good_s = set(['SEP', 'REVOKE', 'ZONE'])
        good_f = 0x181
        from_flags = dns.rdtypes.ANY.DNSKEY.flags_to_text_set(good_f)
        self.failUnless(from_flags == good_s,
                        '"%s" != "%s"' % (from_flags, good_s))
        from_text = dns.rdtypes.ANY.DNSKEY.flags_from_text_set(good_s)
        self.failUnless(from_text == good_f,
                        '"0x%x" != "0x%x"' % (from_text, good_f))

    def testFlagsUnknownToText(self):
        '''Test that undefined flags are returned in hexadecimal notation.'''
        unk_s = set(['0x8000'])
        flags_s = dns.rdtypes.ANY.DNSKEY.flags_to_text_set(0x8000)
        self.failUnless(flags_s == unk_s, '"%s" != "%s"' % (flags_s, unk_s))

    def testFlagsUnknownToFlags(self):
        '''Test that conversion from undefined mnemonic raises error.'''
        self.failUnlessRaises(NotImplementedError,
                              dns.rdtypes.ANY.DNSKEY.flags_from_text_set,
                              (['0x8000']))

    def testFlagsRRToText(self):
        '''Test that RR method returns correct flags.'''
        rr = dns.rrset.from_text('foo', 300, 'IN', 'DNSKEY', '257 3 8 KEY=')[0]
        rr_s = set(['ZONE', 'SEP'])
        flags_s = rr.flags_to_text_set()
        self.failUnless(flags_s == rr_s, '"%s" != "%s"' % (flags_s, rr_s))


if __name__ == '__main__':
    unittest.main()
