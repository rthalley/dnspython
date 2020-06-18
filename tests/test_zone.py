# -*- coding: utf-8
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

from io import BytesIO, StringIO
import difflib
import os
import sys
import unittest
from typing import cast

import dns.exception
import dns.message
import dns.name
import dns.node
import dns.rdata
import dns.rdataset
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone
import dns.node

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

# No $TTL so default TTL for RRs should be inherited from SOA minimum TTL (
# not from the last explicit RR TTL).
ttl_from_soa_text = """$ORIGIN example.
@ 1h soa foo bar 1 2 3 4 5
@ 1h ns ns1
@ 1h ns ns2
ns1 1w1D1h1m1S a 10.0.0.2
ns2 a 10.0.0.1
"""

# No $TTL and no SOA, so default TTL for RRs should be inherited from last
# explicit RR TTL.
ttl_from_last_text = """$ORIGIN example.
@ 1h ns ns1
@ 1h ns ns2
ns1 a 10.0.0.1
ns2 1w1D1h1m1S a 10.0.0.2
"""

# No $TTL and no SOA should raise SyntaxError as no TTL can be determined.
no_ttl_text = """$ORIGIN example.
@ ns ns1
@ ns ns2
ns1 a 10.0.0.1
ns2 a 10.0.0.2
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

codec_text = """
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
Königsgäßchen 300 NS Königsgäßchen
"""

misc_cases_input = """
$ORIGIN example.
$TTL 300
      
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
out-of-zone. in a 10.0.0.1
"""

misc_cases_expected = """
$ORIGIN example.
$TTL 300
@ soa foo bar 1 2 3 4 5
@ ns ns1
@ ns ns2
"""

last_ttl_input = """
$ORIGIN example.
@ 300 ns ns1
@ 300 ns ns2
foo a 10.0.0.1
@ soa foo bar 1 2 3 4 5
"""

origin_sets_input = """
$ORIGIN example.
@ soa foo bar 1 2 3 4 5
@ 300 ns ns1
@ 300 ns ns2
"""

_keep_output = True

def _rdata_sort(a):
    return (a[0], a[2].rdclass, a[2].to_text())

def add_rdataset(msg, name, rds):
    rrset = msg.get_rrset(msg.answer, name, rds.rdclass, rds.rdtype,
                          create=True, force_unique=True)
    for rd in rds:
        rrset.add(rd, ttl=rds.ttl)

def make_xfr(zone):
    q = dns.message.make_query(zone.origin, 'AXFR')
    msg = dns.message.make_response(q)
    if zone.relativize:
        msg.origin = zone.origin
        soa_name = dns.name.empty
    else:
        soa_name = zone.origin
    soa = zone.find_rdataset(soa_name, 'SOA')
    add_rdataset(msg, soa_name, soa)
    for (name, rds) in zone.iterate_rdatasets():
        if rds.rdtype == dns.rdatatype.SOA:
            continue
        add_rdataset(msg, name, rds)
    add_rdataset(msg, soa_name, soa)
    return [msg]

def compare_files(test_name, a_name, b_name):
    with open(a_name, 'r') as a:
        with open(b_name, 'r') as b:
            differences = list(difflib.unified_diff(a.readlines(),
                                                    b.readlines()))
            if len(differences) == 0:
                return True
            else:
                print(f'{test_name} differences:')
                sys.stdout.writelines(differences)
                return False

class ZoneTestCase(unittest.TestCase):

    def testFromFile1(self): # type: () -> None
        z = dns.zone.from_file(here('example'), 'example')
        ok = False
        try:
            z.to_file(here('example1.out'), nl=b'\x0a')
            ok = compare_files('testFromFile1',
                               here('example1.out'),
                               here('example1.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example1.out'))
        self.assertTrue(ok)

    def testFromFile2(self): # type: () -> None
        z = dns.zone.from_file(here('example'), 'example', relativize=False)
        ok = False
        try:
            z.to_file(here('example2.out'), relativize=False, nl=b'\x0a')
            ok = compare_files('testFromFile2',
                               here('example2.out'),
                               here('example2.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example2.out'))
        self.assertTrue(ok)

    def testToFileTextualStream(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        f = StringIO()
        z.to_file(f)
        out = f.getvalue()
        f.close()
        self.assertEqual(out, example_text_output)

    def testToFileBinaryStream(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        f = BytesIO()
        z.to_file(f, nl=b'\n')
        out = f.getvalue()
        f.close()
        self.assertEqual(out, example_text_output.encode())

    def testToFileTextual(self): # type: () -> None
        z = dns.zone.from_file(here('example'), 'example')
        try:
            f = open(here('example3-textual.out'), 'w')
            z.to_file(f)
            f.close()
            ok = compare_files('testToFileTextual',
                               here('example3-textual.out'),
                               here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3-textual.out'))
        self.assertTrue(ok)

    def testToFileBinary(self): # type: () -> None
        z = dns.zone.from_file(here('example'), 'example')
        try:
            f = open(here('example3-binary.out'), 'wb')
            z.to_file(f)
            f.close()
            ok = compare_files('testToFileBinary',
                               here('example3-binary.out'),
                               here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3-binary.out'))
        self.assertTrue(ok)

    def testToFileFilename(self): # type: () -> None
        z = dns.zone.from_file(here('example'), 'example')
        try:
            z.to_file(here('example3-filename.out'))
            ok = compare_files('testToFileFilename',
                               here('example3-filename.out'),
                               here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3-filename.out'))
        self.assertTrue(ok)

    def testToText(self): # type: () -> None
        z = dns.zone.from_file(here('example'), 'example')
        ok = False
        try:
            text_zone = z.to_text(nl='\x0a')
            f = open(here('example3.out'), 'w')
            f.write(text_zone)
            f.close()
            ok = compare_files('testToText',
                               here('example3.out'),
                               here('example3.good'))
        finally:
            if not _keep_output:
                os.unlink(here('example3.out'))
        self.assertTrue(ok)

    def testFromText(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        f = StringIO()
        names = list(z.nodes.keys())
        names.sort()
        for n in names:
            f.write(z[n].to_text(n))
            f.write('\n')
        self.assertEqual(f.getvalue(), example_text_output)

    def testTorture1(self): # type: () -> None
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
                    self.assertEqual(rd, rd2)

    def testEqual(self): # type: () -> None
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(example_text_output, 'example.',
                                relativize=True)
        self.assertEqual(z1, z2)

    def testNotEqual1(self): # type: () -> None
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_quite_similar, 'example.',
                                relativize=True)
        self.assertNotEqual(z1, z2)

    def testNotEqual2(self): # type: () -> None
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_different, 'example.',
                                relativize=True)
        self.assertNotEqual(z1, z2)

    def testNotEqual3(self): # type: () -> None
        z1 = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2 = dns.zone.from_text(something_different, 'example2.',
                                relativize=True)
        self.assertNotEqual(z1, z2)

    def testFindRdataset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.find_rdataset('@', 'soa')
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertEqual(rds, exrds)

    def testFindRdataset2(self): # type: () -> None
        def bad(): # type: () -> None
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            z.find_rdataset('@', 'loc')
        self.assertRaises(KeyError, bad)

    def testFindRRset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.find_rrset('@', 'soa')
        exrrs = dns.rrset.from_text('@', 300, 'IN', 'SOA', 'foo bar 1 2 3 4 5')
        self.assertEqual(rrs, exrrs)

    def testFindRRset2(self): # type: () -> None
        def bad(): # type: () -> None
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            z.find_rrset('@', 'loc')
        self.assertRaises(KeyError, bad)

    def testGetRdataset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.get_rdataset('@', 'soa')
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertEqual(rds, exrds)

    def testGetRdataset2(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = z.get_rdataset('@', 'loc')
        self.assertTrue(rds is None)

    def testGetRRset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.get_rrset('@', 'soa')
        exrrs = dns.rrset.from_text('@', 300, 'IN', 'SOA', 'foo bar 1 2 3 4 5')
        self.assertEqual(rrs, exrrs)

    def testGetRRset2(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rrs = z.get_rrset('@', 'loc')
        self.assertTrue(rrs is None)

    def testReplaceRdataset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rdataset = dns.rdataset.from_text('in', 'ns', 300, 'ns3', 'ns4')
        z.replace_rdataset('@', rdataset)
        rds = z.get_rdataset('@', 'ns')
        self.assertTrue(rds is rdataset)

    def testReplaceRdataset2(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rdataset = dns.rdataset.from_text('in', 'txt', 300, '"foo"')
        z.replace_rdataset('@', rdataset)
        rds = z.get_rdataset('@', 'txt')
        self.assertTrue(rds is rdataset)

    def testDeleteRdataset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        z.delete_rdataset('@', 'ns')
        rds = z.get_rdataset('@', 'ns')
        self.assertTrue(rds is None)

    def testDeleteRdataset2(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        z.delete_rdataset('ns1', 'a')
        node = z.get_node('ns1')
        self.assertTrue(node is None)

    def testNodeFindRdataset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertEqual(rds, exrds)

    def testNodeFindRdataset2(self): # type: () -> None
        def bad(): # type: () -> None
            z = dns.zone.from_text(example_text, 'example.', relativize=True)
            node = z['@']
            node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.assertRaises(KeyError, bad)

    def testNodeGetRdataset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        exrds = dns.rdataset.from_text('IN', 'SOA', 300, 'foo bar 1 2 3 4 5')
        self.assertEqual(rds, exrds)

    def testNodeGetRdataset2(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.assertTrue(rds is None)

    def testNodeDeleteRdataset1(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
        self.assertTrue(rds is None)

    def testNodeDeleteRdataset2(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        node = z['@']
        node.delete_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        rds = node.get_rdataset(dns.rdataclass.IN, dns.rdatatype.LOC)
        self.assertTrue(rds is None)

    def testIterateRdatasets(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        ns = [n for n, r in z.iterate_rdatasets('A')]
        ns.sort()
        self.assertEqual(ns, [dns.name.from_text('ns1', None),
                              dns.name.from_text('ns2', None)])

    def testIterateAllRdatasets(self): # type: () -> None
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        ns = [n for n, r in z.iterate_rdatasets()]
        ns.sort()
        self.assertEqual(ns, [dns.name.from_text('@', None),
                              dns.name.from_text('@', None),
                              dns.name.from_text('bar.foo', None),
                              dns.name.from_text('ns1', None),
                              dns.name.from_text('ns2', None)])

    def testIterateRdatas(self): # type: () -> None
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
        self.assertEqual(l, exl)

    def testIterateAllRdatas(self): # type: () -> None
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
        self.assertEqual(l, exl)

    def testNodeGetSetDel(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        n = z.node_factory()
        rds = dns.rdataset.from_text('IN', 'A', 300, '10.0.0.1')
        n.replace_rdataset(rds)
        z['foo'] = n
        self.assertTrue(z.find_rdataset('foo', 'A') is rds)
        self.assertEqual(z['foo'], n)
        self.assertEqual(z.get('foo'), n)
        del z['foo']
        self.assertEqual(z.get('foo'), None)
        def bad1():
            z[123] = n
        self.assertRaises(KeyError, bad1)
        def bad2():
            z['foo.'] = n
        self.assertRaises(KeyError, bad2)
        def bad3():
            bn = z.find_node('bar')
        self.assertRaises(KeyError, bad3)
        bn = z.find_node('bar', True)
        self.assertTrue(isinstance(bn, dns.node.Node))

    def testBadReplacement(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        rds = dns.rdataset.from_text('CH', 'TXT', 300, 'hi')
        def bad():
            z.replace_rdataset('foo', rds)
        self.assertRaises(ValueError, bad)

    def testTTLs(self): # type: () -> None
        z = dns.zone.from_text(ttl_example_text, 'example.', relativize=True)
        n = z['@'] # type: dns.node.Node
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA))
        self.assertEqual(rds.ttl, 3600)
        n = z['ns1']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A))
        self.assertEqual(rds.ttl, 86401)
        n = z['ns2']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A))
        self.assertEqual(rds.ttl, 694861)

    def testTTLFromSOA(self): # type: () -> None
        z = dns.zone.from_text(ttl_from_soa_text, 'example.', relativize=True)
        n = z['@']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA))
        self.assertEqual(rds.ttl, 3600)
        soa_rd = rds[0]
        n = z['ns1']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A))
        self.assertEqual(rds.ttl, 694861)
        n = z['ns2']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A))
        self.assertEqual(rds.ttl, soa_rd.minimum)

    def testTTLFromLast(self): # type: () -> None
        z = dns.zone.from_text(ttl_from_last_text, 'example.', check_origin=False)
        n = z['@']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.NS))
        self.assertEqual(rds.ttl, 3600)
        n = z['ns1']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A))
        self.assertEqual(rds.ttl, 3600)
        n = z['ns2']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A))
        self.assertEqual(rds.ttl, 694861)

    def testNoTTL(self): # type: () -> None
        def bad(): # type: () -> None
            dns.zone.from_text(no_ttl_text, 'example.', check_origin=False)
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testNoSOA(self): # type: () -> None
        def bad(): # type: () -> None
            dns.zone.from_text(no_soa_text, 'example.', relativize=True)
        self.assertRaises(dns.zone.NoSOA, bad)

    def testNoNS(self): # type: () -> None
        def bad(): # type: () -> None
            dns.zone.from_text(no_ns_text, 'example.', relativize=True)
        self.assertRaises(dns.zone.NoNS, bad)

    def testInclude(self): # type: () -> None
        z1 = dns.zone.from_text(include_text, 'example.', relativize=True,
                                allow_include=True)
        z2 = dns.zone.from_file(here('example'), 'example.', relativize=True)
        self.assertEqual(z1, z2)

    def testBadDirective(self): # type: () -> None
        def bad(): # type: () -> None
            dns.zone.from_text(bad_directive_text, 'example.', relativize=True)
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testFirstRRStartsWithWhitespace(self): # type: () -> None
        # no name is specified, so default to the initial origin
        z = dns.zone.from_text(' 300 IN A 10.0.0.1', origin='example.',
                               check_origin=False)
        n = z['@']
        rds = cast(dns.rdataset.Rdataset, n.get_rdataset(dns.rdataclass.IN, dns.rdatatype.A))
        self.assertEqual(rds.ttl, 300)

    def testZoneOrigin(self): # type: () -> None
        z = dns.zone.Zone('example.')
        self.assertEqual(z.origin, dns.name.from_text('example.'))
        def bad1(): # type: () -> None
            o = dns.name.from_text('example', None)
            dns.zone.Zone(o)
        self.assertRaises(ValueError, bad1)
        def bad2(): # type: () -> None
            dns.zone.Zone(cast(str, 1.0))
        self.assertRaises(ValueError, bad2)

    def testZoneOriginNone(self): # type: () -> None
        dns.zone.Zone(cast(str, None))

    def testZoneFromXFR(self): # type: () -> None
        z1_abs = dns.zone.from_text(example_text, 'example.', relativize=False)
        z2_abs = dns.zone.from_xfr(make_xfr(z1_abs), relativize=False)
        self.assertEqual(z1_abs, z2_abs)

        z1_rel = dns.zone.from_text(example_text, 'example.', relativize=True)
        z2_rel = dns.zone.from_xfr(make_xfr(z1_rel), relativize=True)
        self.assertEqual(z1_rel, z2_rel)

    def testCodec2003(self):
        z = dns.zone.from_text(codec_text, 'example.', relativize=True)
        n2003 = dns.name.from_text('xn--knigsgsschen-lcb0w', None)
        n2008 = dns.name.from_text('xn--knigsgchen-b4a3dun', None)
        self.assertTrue(n2003 in z)
        self.assertFalse(n2008 in z)
        rrs = z.find_rrset(n2003, 'NS')
        self.assertEqual(rrs[0].target, n2003)

    @unittest.skipUnless(dns.name.have_idna_2008,
                         'Python idna cannot be imported; no IDNA2008')
    def testCodec2008(self):
        z = dns.zone.from_text(codec_text, 'example.', relativize=True,
                               idna_codec=dns.name.IDNA_2008)
        n2003 = dns.name.from_text('xn--knigsgsschen-lcb0w', None)
        n2008 = dns.name.from_text('xn--knigsgchen-b4a3dun', None)
        self.assertFalse(n2003 in z)
        self.assertTrue(n2008 in z)
        rrs = z.find_rrset(n2008, 'NS')
        self.assertEqual(rrs[0].target, n2008)

    def testZoneMiscCases(self):
        # test that leading whitespace folllowed by EOL is treated like
        # a blank line, and that out-of-zone names are dropped.
        z1 = dns.zone.from_text(misc_cases_input, 'example.')
        z2 = dns.zone.from_text(misc_cases_expected, 'example.')
        self.assertEqual(z1, z2)

    def testUnknownOrigin(self):
        def bad():
            dns.zone.from_text('foo 300 in a 10.0.0.1')
        self.assertRaises(dns.zone.UnknownOrigin, bad)

    def testBadClass(self):
        def bad():
            dns.zone.from_text('foo 300 ch txt hi', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testUnknownRdatatype(self):
        def bad():
            dns.zone.from_text('foo 300 BOGUSTYPE hi', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testDangling(self):
        def bad1():
            dns.zone.from_text('foo', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad1)
        def bad2():
            dns.zone.from_text('foo 300', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad2)
        def bad3():
            dns.zone.from_text('foo 300 in', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad3)
        def bad4():
            dns.zone.from_text('foo 300 in a', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad4)
        def bad5():
            dns.zone.from_text('$TTL', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad5)
        def bad6():
            dns.zone.from_text('$ORIGIN', 'example.')
        self.assertRaises(dns.exception.SyntaxError, bad6)

    def testUseLastTTL(self):
        z = dns.zone.from_text(last_ttl_input, 'example.')
        rds = z.find_rdataset('foo', 'A')
        self.assertEqual(rds.ttl, 300)

    def testDollarOriginSetsZoneOriginIfUnknown(self):
        z = dns.zone.from_text(origin_sets_input)
        self.assertEqual(z.origin, dns.name.from_text('example'))

    def testValidateNameRelativizesNameInZone(self):
        z = dns.zone.from_text(example_text, 'example.', relativize=True)
        self.assertEqual(z._validate_name('foo.bar.example.'),
                         dns.name.from_text('foo.bar', None))

if __name__ == '__main__':
    unittest.main()
