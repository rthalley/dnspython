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

from io import BytesIO, StringIO
import filecmp
import os
try:
    import unittest2 as unittest
except ImportError:
    import unittest

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone

def here(filename):
    return os.path.join(os.path.dirname(__file__), filename)

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

include_text = """$INCLUDE "%s"
""" % here("example")

bad_directive_text = """$FOO bar
$ORIGIN example.
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
ns1 1d1s a 10.0.0.1
ns2 1w1D1h1m1S a 10.0.0.2
"""

_keep_output = True

def _rdata_sort(a):
    return (a[0], a[2].rdclass, a[2].to_text())

class ZoneTestCase(unittest.TestCase):

    def testFromFile1(self):
        z = dns.zone.from_file(here('example'), 'example')
        ok = False
        try:
            z.to_file(here('example1.out'), nl=b'\x0a')
            ok = filecmp.cmp(here('example1.out'),
                             here('example1.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example1.out'))
        self.failUnless(ok)

    def testFromFile2(self):
        z = dns.zone.from_file(here('example'), 'example', relativize=False)
        ok = False
        try:
            z.to_file(here('example2.out'), relativize=False, nl=b'\x0a')
            ok = filecmp.cmp(here('example2.out'),
                             here('example2.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example2.out'))
        self.failUnless(ok)

    def testToFileTextualStream(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        f = StringIO()
        z.to_file(f)
        out = f.getvalue()
        f.close()
        self.assertEqual(out, example_text_output)

    def testToFileBinaryStream(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        f = BytesIO()
        z.to_file(f)
        out = f.getvalue()
        f.close()
        self.assertEqual(out, example_text_output.encode())

    def testToFileTextual(self):
        z = dns.zone.from_file(here('example'), 'example')
        try:
            f = open(here('example3-textual.out'), 'w')
            z.to_file(f)
            f.close()
            ok = filecmp.cmp(here('example3-textual.out'),
                             here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3-textual.out'))
        self.failUnless(ok)

    def testToFileBinary(self):
        z = dns.zone.from_file(here('example'), 'example')
        try:
            f = open(here('example3-binary.out'), 'wb')
            z.to_file(f)
            f.close()
            ok = filecmp.cmp(here('example3-binary.out'),
                             here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3-binary.out'))
        self.failUnless(ok)

    def testToFileFilename(self):
        z = dns.zone.from_file(here('example'), 'example')
        try:
            z.to_file('example3-filename.out')
            ok = filecmp.cmp(here('example3-filename.out'),
                             here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3-filename.out'))
        self.failUnless(ok)

    def testToText(self):
        z = dns.zone.from_file(here('example'), 'example')
        ok = False
        try:
            text_zone = z.to_text(nl=b'\x0a')
            f = open(here('example3.out'), 'wb')
            f.write(text_zone)
            f.close()
            ok = filecmp.cmp(here('example3.out'),
                             here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3.out'))
        self.failUnless(ok)

    def testFromText(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        f = StringIO()
        names = list(z.nodes.keys())
        names.sort()
        for n in names:
            f.write(z[n].to_text(n))
            f.write(u'\n')
        self.assertEqual(f.getvalue(), example_text_output)

    def testTorture1(self):
        #
        # Read a zone containing all our supported RR types, and
        # for each RR in the zone, convert the rdata into wire format
        # and then back out, and see if we get equal rdatas.
        #
        f = BytesIO()
        o = dns.name.from_text('example.')
        z = dns.zone.from_file(here('example'), o)
        for node in z.values():
            for rds in node:
                for rd in rds:
                    f.seek(0)
                    f.truncate()
                    rd.to_wire(f, origin=o)
                    wire = f.getvalue()
                    rd2 = dns.rdata.from_wire(rds.rdclass, rds.rdtype,
                                              wire, 0, len(wire),
                                              origin=o)
                    self.failUnless(rd == rd2)

    def testEqual(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(example_text_output, 'example.',
                                relativize=True)
        self.failUnless(z1 == z2)

    def testNotEqual1(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_quite_similar, 'example.',
                                relativize=True)
        self.failUnless(z1 != z2)

    def testNotEqual2(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_different, 'example.',
                                relativize=True)
        self.failUnless(z1 != z2)

    def testNotEqual3(self):
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_different, 'example2.',
                                relativize=True)
        self.failUnless(z1 != z2)

    def testFindRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.find_rdataset('@', 'soa')
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.failUnless(rds == exrds)

    def testFindRdataset2(self):
        def bad():
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            z.find_rdataset('@', 'loc')
        self.failUnlessRaises(KeyError, bad)

    def testFindRRset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.find_rrset('@', 'soa')
        exrrs = dns.rrset.from_text('@', 300, 'IN', 'SOA', 'foo bar 1 2 3 4 5')
        self.failUnless(rrs == exrrs)

    def testFindRRset2(self):
        def bad():
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            z.find_rrset('@', 'loc')
        self.failUnlessRaises(KeyError, bad)

    def testGetRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.get_rdataset('@', 'soa')
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.failUnless(rds == exrds)

    def testGetRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.get_rdataset('@', 'loc')
        self.failUnless(rds is None)

    def testGetRRset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.get_rrset('@', 'soa')
        exrrs = dns.rrset.from_text('@', 300, 'IN', 'SOA', 'foo bar 1 2 3 4 5')
        self.failUnless(rrs == exrrs)

    def testGetRRset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.get_rrset('@', 'loc')
        self.failUnless(rrs is None)

    def testReplaceRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rdataset = dns.rdataset.from_text('in', 'ns', 300, 'ns3', 'ns4')
        z.replace_rdataset('@', rdataset)
        rds = z.get_rdataset('@', 'ns')
        self.failUnless(rds is rdataset)

    def testReplaceRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rdataset = dns.rdataset.from_text('in', 'txt', 300, '"foo"')
        z.replace_rdataset('@', rdataset)
        rds = z.get_rdataset('@', 'txt')
        self.failUnless(rds is rdataset)

    def testDeleteRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        z.delete_rdataset('@', 'ns')
        rds = z.get_rdataset('@', 'ns')
        self.failUnless(rds is None)

    def testDeleteRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        z.delete_rdataset('ns1', 'a')
        node = z.get_node('ns1')
        self.failUnless(node is None)

    def testNodeFindRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.failUnless(rds == exrds)

    def testNodeFindRdataset2(self):
        def bad():
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            node = z['@']
            node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.failUnlessRaises(KeyError, bad)

    def testNodeGetRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.failUnless(rds == exrds)

    def testNodeGetRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.failUnless(rds is None)

    def testNodeDeleteRdataset1(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        self.failUnless(rds is None)

    def testNodeDeleteRdataset2(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.failUnless(rds is None)

    def testIterateRdatasets(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        ns = [n for n, r in z.iterate_rdatasets('A')]
        ns.sort()
        self.failUnless(ns == [dns.name.from_text('ns1', None),
                               dns.name.from_text('ns2', None)])

    def testIterateAllRdatasets(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        ns = [n for n, r in z.iterate_rdatasets()]
        ns.sort()
        self.failUnless(ns == [dns.name.from_text('@', None),
                               dns.name.from_text('@', None),
                               dns.name.from_text('bar.foo', None),
                               dns.name.from_text('ns1', None),
                               dns.name.from_text('ns2', None)])

    def testIterateRdatas(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        l = list(z.iterate_rdatas('A'))
        l.sort()
        exl = [(dns.name.from_text('ns1', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.1')),
               (dns.name.from_text('ns2', None),
                3600,
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.2'))]
        self.failUnless(l == exl)

    def testIterateAllRdatas(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        l = list(z.iterate_rdatas())
        l.sort(key=_rdata_sort)
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
        exl.sort(key=_rdata_sort)
        self.failUnless(l == exl)

    def testTTLs(self):
        z = dns.zone.from_text(ttl_example_text, 'example.', relativize=True)
        n = z['@']
        rds = n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        self.failUnless(rds.ttl == 3600)
        n = z['ns1']
        rds = n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
        self.failUnless(rds.ttl == 86401)
        n = z['ns2']
        rds = n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
        self.failUnless(rds.ttl == 694861)

    def testNoSOA(self):
        def bad():
            dns.zone.from_text(no_soa_text, 'example.', relativize=True)
        self.failUnlessRaises(dns.zone.NoSOA, bad)

    def testNoNS(self):
        def bad():
            dns.zone.from_text(no_ns_text, 'example.', relativize=True)
        self.failUnlessRaises(dns.zone.NoNS, bad)

    def testInclude(self):
        z1 = dns.zone.from_text(include_text, 'example.', relativize=True,
                                allow_include=True)
        z2 = dns.zone.from_file(here('example'), 'example.', relativize=True)
        self.failUnless(z1 == z2)

    def testBadDirective(self):
        def bad():
            dns.zone.from_text(bad_directive_text, 'example.', relativize=True)
        self.failUnlessRaises(dns.exception.SyntaxError, bad)

    def testFirstRRStartsWithWhitespace(self):
        # no name is specified, so default to the initial origin
        # no ttl is specified, so default to the initial TTL of 0
        z = dns.zone.from_text(' IN A 10.0.0.1', origin='example.',
                               check_origin=False)
        n = z['@']
        rds = n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A)
        self.failUnless(rds.ttl == 0)

    def testZoneOrigin(self):
        z = dns.zone.Zone('example.')
        self.failUnless(z.origin == dns.name.from_text('example.'))
        def bad1():
            o = dns.name.from_text('example', None)
            dns.zone.Zone(o)
        self.failUnlessRaises(ValueError, bad1)
        def bad2():
            dns.zone.Zone(1.0)
        self.failUnlessRaises(ValueError, bad2)

    def testZoneOriginNone(self):
        dns.zone.Zone(None)

if __name__ == '__main__':
    unittest.main()
