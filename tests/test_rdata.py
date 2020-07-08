# -*- coding: utf-8
# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

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

import binascii
import io
import operator
import pickle
import struct
import unittest

import dns.wire
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
from dns.rdtypes.ANY.OPT import OPT

import tests.stxt_module
import tests.ttxt_module

class RdataTestCase(unittest.TestCase):

    def test_str(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    "1.2.3.4")
        self.assertEqual(rdata.address, "1.2.3.4")

    def test_unicode(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    u"1.2.3.4")
        self.assertEqual(rdata.address, "1.2.3.4")

    def test_module_registration(self):
        TTXT = 64001
        dns.rdata.register_type(tests.ttxt_module, TTXT, 'TTXT')
        rdata = dns.rdata.from_text(dns.rdataclass.IN, TTXT, 'hello world')
        self.assertEqual(rdata.strings, (b'hello', b'world'))
        self.assertEqual(dns.rdatatype.to_text(TTXT), 'TTXT')
        self.assertEqual(dns.rdatatype.from_text('TTXT'), TTXT)

    def test_module_reregistration(self):
        def bad():
            TTXTTWO = dns.rdatatype.TXT
            dns.rdata.register_type(tests.ttxt_module, TTXTTWO, 'TTXTTWO')
        self.assertRaises(dns.rdata.RdatatypeExists, bad)

    def test_module_registration_singleton(self):
        STXT = 64002
        dns.rdata.register_type(tests.stxt_module, STXT, 'STXT',
                                is_singleton=True)
        rdata1 = dns.rdata.from_text(dns.rdataclass.IN, STXT, 'hello')
        rdata2 = dns.rdata.from_text(dns.rdataclass.IN, STXT, 'world')
        rdataset = dns.rdataset.from_rdata(3600, rdata1, rdata2)
        self.assertEqual(len(rdataset), 1)
        self.assertEqual(rdataset[0].strings, (b'world',))

    def test_replace(self):
        a1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        a2 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "2.3.4.5")
        self.assertEqual(a1.replace(address="2.3.4.5"), a2)

        mx = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX,
                                  "10 foo.example")
        name = dns.name.from_text("bar.example")
        self.assertEqual(mx.replace(preference=20).preference, 20)
        self.assertEqual(mx.replace(preference=20).exchange, mx.exchange)
        self.assertEqual(mx.replace(exchange=name).exchange, name)
        self.assertEqual(mx.replace(exchange=name).preference, mx.preference)

        for invalid_parameter in ("rdclass", "rdtype", "foo", "__class__"):
            with self.assertRaises(AttributeError):
                mx.replace(invalid_parameter=1)

    def test_invalid_replace(self):
        a1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        def bad():
            a1.replace(address="bogus")
        self.assertRaises(dns.exception.SyntaxError, bad)

    def test_to_generic(self):
        a = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        self.assertEqual(str(a.to_generic()), r'\# 4 01020304')

        mx = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, "10 foo.")
        self.assertEqual(str(mx.to_generic()), r'\# 7 000a03666f6f00')

        origin = dns.name.from_text('example')
        ns = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS,
                                 "foo.example.", relativize_to=origin)
        self.assertEqual(str(ns.to_generic(origin=origin)),
                         r'\# 13 03666f6f076578616d706c6500')

    def test_txt_unicode(self):
        # TXT records are not defined for Unicode, but if we get
        # Unicode we should convert it to UTF-8 to preserve meaning as
        # best we can.  Note that it when the TXT record is sent
        # to_text(), it does NOT convert embedded UTF-8 back to
        # Unicode; it's just treated as binary TXT data.  Probably
        # there should be a TXT-like record with an encoding field.
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT,
                                    '"foo\u200bbar"')
        self.assertEqual(str(rdata), '"foo\\226\\128\\139bar"')
        # We used to encode UTF-8 in UTF-8 because we processed
        # escapes in quoted strings immediately.  This meant that the
        # \\226 below would be inserted as Unicode code point 226, and
        # then when we did to_text, we would UTF-8 encode that code
        # point, emitting \\195\\162 instead of \\226, and thus
        # from_text followed by to_text was not the equal to the
        # original input like it ought to be.
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT,
                                    '"foo\\226\\128\\139bar"')
        self.assertEqual(str(rdata), '"foo\\226\\128\\139bar"')
        # Our fix for TXT-like records uses a new tokenizer method,
        # unescape_to_bytes(), which converts Unicode to UTF-8 only
        # once.
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT,
                                    '"foo\u200b\\123bar"')
        self.assertEqual(str(rdata), '"foo\\226\\128\\139{bar"')

    def test_unicode_idna2003_in_rdata(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS,
                                    "Königsgäßchen")
        self.assertEqual(str(rdata.target), 'xn--knigsgsschen-lcb0w')

    @unittest.skipUnless(dns.name.have_idna_2008,
                         'Python idna cannot be imported; no IDNA2008')
    def test_unicode_idna2008_in_rdata(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS,
                                    "Königsgäßchen",
                                    idna_codec=dns.name.IDNA_2008)
        self.assertEqual(str(rdata.target), 'xn--knigsgchen-b4a3dun')

    def test_digestable_downcasing(self):
        # Make sure all the types listed in RFC 4034 section 6.2 are
        # downcased properly, except for:
        #
        #   types we don't implement:  MD, MF, MB, MG, MR, MINFO, SIG,
        #                              NXT, A6
        #
        #   types that don't have names: HINFO
        #
        #   NSEC3, whose downcasing was removed by RFC 6840 section 5.1
        #
        cases = [
            ('SOA', 'NAME NAME 1 2 3 4 5'),
            ('AFSDB', '0 NAME'),
            ('CNAME', 'NAME'),
            ('DNAME', 'NAME'),
            ('KX', '10 NAME'),
            ('MX', '10 NAME'),
            ('NS', 'NAME'),
            ('NAPTR', '0 0 a B c NAME'),
            ('PTR', 'NAME'),
            ('PX', '65535 NAME NAME'),
            ('RP', 'NAME NAME'),
            ('RT', '0 NAME'),
            ('SRV', '0 0 0 NAME'),
            ('RRSIG',
             'A 1 3 3600 20200701000000 20200601000000 1 NAME Ym9ndXM=')
        ]
        for rdtype, text in cases:
            upper_origin = dns.name.from_text('EXAMPLE')
            lower_origin = dns.name.from_text('example')
            canonical_text = text.replace('NAME', 'name')
            rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, text,
                                        origin=upper_origin, relativize=False)
            canonical_rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype,
                                                  canonical_text,
                                                  origin=lower_origin,
                                                  relativize=False)
            digestable_wire = rdata.to_digestable()
            f = io.BytesIO()
            canonical_rdata.to_wire(f)
            expected_wire = f.getvalue()
            self.assertEqual(digestable_wire, expected_wire)

    def test_digestable_no_downcasing(self):
        # Make sure that currently known types with domain names that
        # are NOT supposed to be downcased when canonicalized are
        # handled properly.
        #
        cases = [
            ('HIP', '2 200100107B1A74DF365639CC39F1D578 Ym9ndXM= NAME name'),
            ('IPSECKEY', '10 3 2 NAME Ym9ndXM='),
            ('NSEC', 'NAME A'),
        ]
        for rdtype, text in cases:
            origin = dns.name.from_text('example')
            rdata = dns.rdata.from_text(dns.rdataclass.IN, rdtype, text,
                                        origin=origin, relativize=False)
            digestable_wire = rdata.to_digestable(origin)
            expected_wire = rdata.to_wire(origin=origin)
            self.assertEqual(digestable_wire, expected_wire)

    def test_basic_relations(self):
        r1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                 '10.0.0.1')
        r2 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                 '10.0.0.2')
        self.assertTrue(r1 == r1)
        self.assertTrue(r1 != r2)
        self.assertTrue(r1 < r2)
        self.assertTrue(r1 <= r2)
        self.assertTrue(r2 > r1)
        self.assertTrue(r2 >= r1)

    def test_incompatible_relations(self):
        r1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                 '10.0.0.1')
        r2 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA,
                                 '::1')
        for oper in [operator.lt, operator.le, operator.ge, operator.gt]:
            self.assertRaises(TypeError, lambda: oper(r1, r2))
        self.assertFalse(r1 == r2)
        self.assertTrue(r1 != r2)

    def test_immutability(self):
        def bad1():
            r = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.1')
            r.address = '10.0.0.2'
        self.assertRaises(TypeError, bad1)
        def bad2():
            r = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.1')
            del r.address
        self.assertRaises(TypeError, bad2)

    def test_pickle(self):
        r1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                 '10.0.0.1')
        p = pickle.dumps(r1)
        r2 = pickle.loads(p)
        self.assertEqual(r1, r2)
        # Pickle something with a longer inheritance chain
        r3 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX,
                                 '10 mail.example.')
        p = pickle.dumps(r3)
        r4 = pickle.loads(p)
        self.assertEqual(r3, r4)

    def test_AFSDB_properties(self):
        rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AFSDB,
                                 '0 afsdb.example.')
        self.assertEqual(rd.preference, rd.subtype)
        self.assertEqual(rd.exchange, rd.hostname)

    def equal_loc(self, a, b):
        rda = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.LOC, a)
        rdb = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.LOC, b)
        self.assertEqual(rda, rdb)

    def test_misc_good_LOC_text(self):
        # test variable length latitude
        self.equal_loc('60 9 0.510 N 24 39 0.000 E 10.00m 20m 2000m 20m',
                       '60 9 0.51 N 24 39 0.000 E 10.00m 20m 2000m 20m')
        self.equal_loc('60 9 0.500 N 24 39 0.000 E 10.00m 20m 2000m 20m',
                       '60 9 0.5 N 24 39 0.000 E 10.00m 20m 2000m 20m')
        self.equal_loc('60 9 1.000 N 24 39 0.000 E 10.00m 20m 2000m 20m',
                       '60 9 1 N 24 39 0.000 E 10.00m 20m 2000m 20m')
        # test variable length longtitude
        self.equal_loc('60 9 0.000 N 24 39 0.510 E 10.00m 20m 2000m 20m',
                       '60 9 0.000 N 24 39 0.51 E 10.00m 20m 2000m 20m')
        self.equal_loc('60 9 0.000 N 24 39 0.500 E 10.00m 20m 2000m 20m',
                       '60 9 0.000 N 24 39 0.5 E 10.00m 20m 2000m 20m')
        self.equal_loc('60 9 0.000 N 24 39 1.000 E 10.00m 20m 2000m 20m',
                       '60 9 0.000 N 24 39 1 E 10.00m 20m 2000m 20m')

    def test_bad_LOC_text(self):
        bad_locs = ['60 9 a.000 N 24 39 0.000 E 10.00m 20m 2000m 20m',
                    '60 9 60.000 N 24 39 0.000 E 10.00m 20m 2000m 20m',
                    '60 9 0.00a N 24 39 0.000 E 10.00m 20m 2000m 20m',
                    '60 9 0.0001 N 24 39 0.000 E 10.00m 20m 2000m 20m',
                    '60 9 0.000 Z 24 39 0.000 E 10.00m 20m 2000m 20m',
                    '91 9 0.000 N 24 39 0.000 E 10.00m 20m 2000m 20m',
                    '60 60 0.000 N 24 39 0.000 E 10.00m 20m 2000m 20m',

                    '60 9 0.000 N 24 39 a.000 E 10.00m 20m 2000m 20m',
                    '60 9 0.000 N 24 39 60.000 E 10.00m 20m 2000m 20m',
                    '60 9 0.000 N 24 39 0.00a E 10.00m 20m 2000m 20m',
                    '60 9 0.000 N 24 39 0.0001 E 10.00m 20m 2000m 20m',
                    '60 9 0.000 N 24 39 0.000 Z 10.00m 20m 2000m 20m',
                    '60 9 0.000 N 181 39 0.000 E 10.00m 20m 2000m 20m',
                    '60 9 0.000 N 24 60 0.000 E 10.00m 20m 2000m 20m',

                    '60 9 0.000 N 24 39 0.000 E 10.00m 100000000m 2000m 20m',
                    '60 9 0.000 N 24 39 0.000 E 10.00m 20m 100000000m 20m',
                    '60 9 0.000 N 24 39 0.000 E 10.00m 20m 20m 100000000m',
                    ]
        def bad(text):
            rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.LOC,
                                     text)
        for loc in bad_locs:
            self.assertRaises(dns.exception.SyntaxError,
                              lambda: bad(loc))

    def test_bad_LOC_wire(self):
        bad_locs = [(0, 0, 0, 0x934fd901, 0x80000000, 100),
                    (0, 0, 0, 0x6cb026ff, 0x80000000, 100),
                    (0, 0, 0, 0x80000000, 0xa69fb201, 100),
                    (0, 0, 0, 0x80000000, 0x59604dff, 100),
                    (0xa0, 0, 0, 0x80000000, 0x80000000, 100),
                    (0x0a, 0, 0, 0x80000000, 0x80000000, 100),
                    (0, 0xa0, 0, 0x80000000, 0x80000000, 100),
                    (0, 0x0a, 0, 0x80000000, 0x80000000, 100),
                    (0, 0, 0xa0, 0x80000000, 0x80000000, 100),
                    (0, 0, 0x0a, 0x80000000, 0x80000000, 100),
                    ]
        for t in bad_locs:
            wire = struct.pack('!BBBBIII', 0, t[0], t[1], t[2],
                               t[3], t[4], t[5])
            self.assertRaises(dns.exception.FormError,
                              lambda: dns.rdata.from_wire(dns.rdataclass.IN,
                                                          dns.rdatatype.LOC,
                                                          wire, 0, len(wire)))

    def equal_wks(self, a, b):
        rda = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.WKS, a)
        rdb = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.WKS, b)
        self.assertEqual(rda, rdb)

    def test_misc_good_WKS_text(self):
        self.equal_wks('10.0.0.1 tcp ( http )', '10.0.0.1 6 ( 80 )')
        self.equal_wks('10.0.0.1 udp ( domain )', '10.0.0.1 17 ( 53 )')

    def test_misc_bad_WKS_text(self):
        def bad():
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.WKS,
                                '10.0.0.1 132 ( domain )')
        self.assertRaises(NotImplementedError, bad)

    def test_bad_GPOS_text(self):
        bad_gpos = ['"-" "116.8652" "250"',
                    '"+" "116.8652" "250"',
                    '"" "116.8652" "250"',
                    '"." "116.8652" "250"',
                    '".a" "116.8652" "250"',
                    '"a." "116.8652" "250"',
                    '"a.a" "116.8652" "250"',
                    # We don't need to test all the bad permutations again
                    # but we do want to test that badness is detected
                    # in the other strings
                    '"0" "a" "250"',
                    '"0" "0" "a"',
                    # finally test bounds
                    '"90.1" "0" "0"',
                    '"-90.1" "0" "0"',
                    '"0" "180.1" "0"',
                    '"0" "-180.1" "0"',
                    ]
        def bad(text):
            rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.GPOS,
                                     text)
        for gpos in bad_gpos:
            self.assertRaises(dns.exception.FormError,
                              lambda: bad(gpos))

    def test_bad_GPOS_wire(self):
        bad_gpos = [b'\x01',
                    b'\x01\x31\x01',
                    b'\x01\x31\x01\x31\x01',
                    ]
        for wire in bad_gpos:
            self.assertRaises(dns.exception.FormError,
                              lambda: dns.rdata.from_wire(dns.rdataclass.IN,
                                                          dns.rdatatype.GPOS,
                                                          wire, 0, len(wire)))

    def test_chaos(self):
        # avoid red spot on our coverage :)
        r1 = dns.rdata.from_text(dns.rdataclass.CH, dns.rdatatype.A,
                                 'chaos. 12345')
        w = r1.to_wire()
        r2 = dns.rdata.from_wire(dns.rdataclass.CH, dns.rdatatype.A, w, 0,
                                 len(w))
        self.assertEqual(r1, r2)
        self.assertEqual(r1.domain, dns.name.from_text('chaos'))
        # the address input is octal
        self.assertEqual(r1.address, 0o12345)
        self.assertEqual(r1.to_text(), 'chaos. 12345')

    def test_opt_repr(self):
        opt = OPT(4096, dns.rdatatype.OPT, ())
        self.assertEqual(repr(opt), '<DNS CLASS4096 OPT rdata: >')

    def test_opt_short_lengths(self):
        def bad1():
            parser = dns.wire.Parser(bytes.fromhex('f00102'))
            opt = OPT.from_wire_parser(4096, dns.rdatatype.OPT, parser)
        self.assertRaises(dns.exception.FormError, bad1)
        def bad2():
            parser = dns.wire.Parser(bytes.fromhex('f00100030000'))
            opt = OPT.from_wire_parser(4096, dns.rdatatype.OPT, parser)
        self.assertRaises(dns.exception.FormError, bad2)

    def test_from_wire_parser(self):
        wire = bytes.fromhex('01020304')
        rdata = dns.rdata.from_wire('in', 'a', wire, 0, 4)
        self.assertEqual(rdata, dns.rdata.from_text('in', 'a', '1.2.3.4'))

if __name__ == '__main__':
    unittest.main()
