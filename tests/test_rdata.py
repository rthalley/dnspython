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

import io
import unittest

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype

import tests.stxt_module
import tests.ttxt_module

class RdataTestCase(unittest.TestCase):

    def test_str(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        self.assertEqual(rdata.address, "1.2.3.4")

    def test_unicode(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, u"1.2.3.4")
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
        #   types where the canonical form isn't relevant: RRSIG
        #
        cases = [
            ('SOA', 'NAME NAME 1 2 3 4 5'),
            ('AFSDB', '0 NAME'),
            ('CNAME', 'NAME'),
            ('DNAME', 'NAME'),
            ('KX', '10 NAME'),
            ('MX', '10 NAME'),
            ('NS', 'NAME'),
            ('NSEC', 'NAME A'),
            ('NAPTR', '0 0 a B c NAME'),
            ('PTR', 'NAME'),
            ('PX', '65535 NAME NAME'),
            ('RP', 'NAME NAME'),
            ('RT', '0 NAME'),
            ('SRV', '0 0 0 NAME'),
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

if __name__ == '__main__':
    unittest.main()
