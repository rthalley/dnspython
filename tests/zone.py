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

import io
import filecmp
import os
import unittest

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone

example_text = """$TTL 3600
$ORIGIN example.
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
ns1 a 10.0.0.1
ns2 a 10.0.0.2
$TTL 300
$ORIGIN foo.example.
bar mx 0 blaz
"""

example_text_output = """@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
"""

something_quite_similar = """@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.3
"""

something_different = """@ 3600 IN SOA fooa bar 1 2 3 4 5
@ 3600 IN NS ns11
@ 3600 IN NS ns21
bar.fooa 300 IN MX 0 blaz.fooa
ns11 3600 IN A 10.0.0.11
ns21 3600 IN A 10.0.0.21
"""

ttl_example_text = """$TTL 1h
$ORIGIN example.
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
ns1 1d1s a 10.0.0.1
ns2 1w1D1h1m1S a 10.0.0.2
"""

no_soa_text = """$TTL 1h
$ORIGIN example.
@ ns ns1
@ ns ns2
ns1 1d1s a 10.0.0.1
ns2 1w1D1h1m1S a 10.0.0.2
"""

no_ns_text = """$TTL 1h
$ORIGIN example.
@ soa foo bar 1 2 3 4 5
"""

include_text = """$INCLUDE "example"
"""

bad_directive_text = """$FOO bar
$ORIGIN example.
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
ns1 1d1s a 10.0.0.1
ns2 1w1D1h1m1S a 10.0.0.2
"""

_keep_output = False

class ZoneTestCase(unittest.TestCase):

    def testFromFile1(self):
        z = dns.zone.from_file('example', 'example')
        ok = False
        try:
            z.to_file('example1.out', nl='\x0a')
            ok = filecmp.cmp('example1.out', 'example1.good')
        finally:
            if not _keep_output:
                os.unlink('example1.out')
        self.assertTrue(ok)

    def testFromFile2(self):
        z = dns.zone.from_file('example', 'example', relativize=False)
        ok = False
        try:
            z.to_file('example2.out', relativize=False, nl='\x0a')
            ok = filecmp.cmp('example2.out', 'example2.good')
        finally:
            if not _keep_output:
                os.unlink('example2.out')
        self.assertTrue(ok)

    def testFromText(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        f = io.StringIO()
        names = sorted(z.nodes.keys())
        for n in names:
            print(z[n].to_text(n), file=f)
        self.assertTrue(f.getvalue() == example_text_output)

    def testTorture1(self):
        #
        # Read a zone containing all our supported RR types, and
        # for each RR in the zone, convert the rdata into wire format
        # and then back out, and see if we get equal rdatas.
        #
        f = io.BytesIO()
        o = dns.name.from_text('example.')
        z = dns.zone.from_file('example', o)
        for (name, node) in z.items():
            for rds in node:
                for rd in rds:
                    f.seek(0)
                    f.truncate()
                    rd.to_wire(f, origin=o)
                    wire = f.getvalue()
                    rd2 = dns.rdata.from_wire(rds.rdclass, rds.rdtype,
                                              wire, 0, len(wire),
                                              origin = o)
                    self.assertTrue(rd == rd2)

    def testEqual(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(example_text_output, 'example.',
                                relativize=True)
        self.assertTrue(z1 == z2)

    def testNotEqual1(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_quite_similar, 'example.',
                                relativize=True)
        self.assertTrue(z1 != z2)

    def testNotEqual2(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_different, 'example.',
                                relativize=True)
        self.assertTrue(z1 != z2)

    def testNotEqual3(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_different, 'example2.',
                                relativize=True)
        self.assertTrue(z1 != z2)

    def testFindRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.find_rdataset('@', 'soa')
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertTrue(rds == exrds)

    def testFindRdataset2(self):
        def bad():
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            rds = z.find_rdataset('@', 'loc')
        self.assertRaises(KeyError, bad)

    def testFindRRset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.find_rrset('@', 'soa')
        exrrs = dns.rrset.from_text('@', 300, 'IN', 'SOA', 'foo bar 1 2 3 4 5')
        self.assertTrue(rrs == exrrs)

    def testFindRRset2(self):
        def bad():
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            rrs = z.find_rrset('@', 'loc')
        self.assertRaises(KeyError, bad)

    def testGetRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.get_rdataset('@', 'soa')
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertTrue(rds == exrds)

    def testGetRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.get_rdataset('@', 'loc')
        self.assertTrue(rds == None)

    def testGetRRset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.get_rrset('@', 'soa')
        exrrs = dns.rrset.from_text('@', 300, 'IN', 'SOA', 'foo bar 1 2 3 4 5')
        self.assertTrue(rrs == exrrs)

    def testGetRRset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.get_rrset('@', 'loc')
        self.assertTrue(rrs == None)

    def testReplaceRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rdataset = dns.rdataset.from_text('in', 'ns', 300, 'ns3', 'ns4')
        z.replace_rdataset('@', rdataset)
        rds = z.get_rdataset('@', 'ns')
        self.assertTrue(rds is rdataset)

    def testReplaceRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rdataset = dns.rdataset.from_text('in', 'txt', 300, '"foo"')
        z.replace_rdataset('@', rdataset)
        rds = z.get_rdataset('@', 'txt')
        self.assertTrue(rds is rdataset)

    def testDeleteRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        z.delete_rdataset('@', 'ns')
        rds = z.get_rdataset('@', 'ns')
        self.assertTrue(rds is None)

    def testDeleteRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        z.delete_rdataset('ns1', 'a')
        node = z.get_node('ns1')
        self.assertTrue(node is None)

    def testNodeFindRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertTrue(rds == exrds)

    def testNodeFindRdataset2(self):
        def bad():
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            node = z['@']
            rds = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.assertRaises(KeyError, bad)

    def testNodeGetRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertTrue(rds == exrds)

    def testNodeGetRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.assertTrue(rds == None)

    def testNodeDeleteRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        self.assertTrue(rds == None)

    def testNodeDeleteRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.assertTrue(rds == None)

    def testIterateRdatasets(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        ns = sorted([n for n, r in z.iterate_rdatasets('A')])
        self.assertTrue(ns == [dns.name.from_text('ns1', None),
                               dns.name.from_text('ns2', None)])

    def testIterateAllRdatasets(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        ns = sorted([n for n, r in z.iterate_rdatasets()])
        self.assertTrue(ns == [dns.name.from_text('@', None),
                               dns.name.from_text('@', None),
                               dns.name.from_text('bar.foo', None),
                               dns.name.from_text('ns1', None),
                               dns.name.from_text('ns2', None)])

    def testIterateRdatas(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        l = sorted(z.iterate_rdatas('A'))
        exl = [(dns.name.from_text('ns1', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.1')),
               (dns.name.from_text('ns2', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.2'))]
        self.assertTrue(l == exl)

    def testIterateAllRdatas(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        l = sorted(z.iterate_rdatas())
        exl = [(dns.name.from_text('@', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS,
                                    'ns1')),
               (dns.name.from_text('@', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS,
                                    'ns2')),
               (dns.name.from_text('@', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA,
                                    'foo bar 1 2 3 4 5')),
               (dns.name.from_text('bar.foo', None),
                300,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX,
                                    '0 blaz.foo')),
               (dns.name.from_text('ns1', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.1')),
               (dns.name.from_text('ns2', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.2'))]
        self.assertTrue(l == exl)

    def testTTLs(self):
        z = dns.zone.from_text(ttl_example_text, 'example.', relativize=True)
        n = z['@']
        rds = n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        self.assertTrue(rds.ttl == 3600)
        n = z['ns1']
        rds = n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rds.ttl == 86401)
        n = z['ns2']
        rds = n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rds.ttl == 694861)

    def testNoSOA(self):
        def bad():
            z = dns.zone.from_text(no_soa_text, 'example.',
                                   relativize=True)
        self.assertRaises(dns.zone.NoSOA, bad)

    def testNoNS(self):
        def bad():
            z = dns.zone.from_text(no_ns_text, 'example.',
                                   relativize=True)
        self.assertRaises(dns.zone.NoNS, bad)

    def testInclude(self):
        z1 = dns.zone.from_text(include_text, 'example.', relativize=True,
                                allow_include=True)
        z2 = dns.zone.from_file('example', 'example.', relativize=True)
        self.assertTrue(z1 == z2)

    def testBadDirective(self):
        def bad():
            z = dns.zone.from_text(bad_directive_text, 'example.',
                                   relativize=True)
        self.assertRaises(dns.exception.SyntaxError, bad)

if __name__ == '__main__':
    unittest.main()
