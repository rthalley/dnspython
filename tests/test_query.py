# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
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

import socket
import unittest

try:
    import ssl
    have_ssl = True
except Exception:
    have_ssl = False

import dns.exception
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.query
import dns.zone

# Some tests require the internet to be available to run, so let's
# skip those if it's not there.
_network_available = True
try:
    socket.gethostbyname('dnspython.org')
except socket.gaierror:
    _network_available = False

# Some tests use a "nano nameserver" for testing.  It requires trio
# and threading, so try to import it and if it doesn't work, skip
# those tests.
try:
    from .nanonameserver import Server
    _nanonameserver_available = True
except ImportError:
    _nanonameserver_available = False
    class Server(object):
        pass

@unittest.skipIf(not _network_available, "Internet not reachable")
class QueryTests(unittest.TestCase):

    def testQueryUDP(self):
        qname = dns.name.from_text('dns.google.')
        q = dns.message.make_query(qname, dns.rdatatype.A)
        response = dns.query.udp(q, '8.8.8.8')
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    def testQueryUDPWithSocket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setblocking(0)
            qname = dns.name.from_text('dns.google.')
            q = dns.message.make_query(qname, dns.rdatatype.A)
            response = dns.query.udp(q, '8.8.8.8', sock=s)
            rrs = response.get_rrset(response.answer, qname,
                                     dns.rdataclass.IN, dns.rdatatype.A)
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue('8.8.8.8' in seen)
            self.assertTrue('8.8.4.4' in seen)

    def testQueryTCP(self):
        qname = dns.name.from_text('dns.google.')
        q = dns.message.make_query(qname, dns.rdatatype.A)
        response = dns.query.tcp(q, '8.8.8.8')
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    def testQueryTCPWithSocket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('8.8.8.8', 53))
            s.setblocking(0)
            qname = dns.name.from_text('dns.google.')
            q = dns.message.make_query(qname, dns.rdatatype.A)
            response = dns.query.tcp(q, None, sock=s)
            rrs = response.get_rrset(response.answer, qname,
                                     dns.rdataclass.IN, dns.rdatatype.A)
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue('8.8.8.8' in seen)
            self.assertTrue('8.8.4.4' in seen)

    def testQueryTLS(self):
        qname = dns.name.from_text('dns.google.')
        q = dns.message.make_query(qname, dns.rdatatype.A)
        response = dns.query.tls(q, '8.8.8.8')
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    @unittest.skipUnless(have_ssl, "No SSL support")
    def testQueryTLSWithSocket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as base_s:
            base_s.connect(('8.8.8.8', 853))
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(base_s, server_hostname='dns.google') as s:
                s.setblocking(0)
                qname = dns.name.from_text('dns.google.')
                q = dns.message.make_query(qname, dns.rdatatype.A)
                response = dns.query.tls(q, None, sock=s)
                rrs = response.get_rrset(response.answer, qname,
                                         dns.rdataclass.IN, dns.rdatatype.A)
                self.assertTrue(rrs is not None)
                seen = set([rdata.address for rdata in rrs])
                self.assertTrue('8.8.8.8' in seen)
                self.assertTrue('8.8.4.4' in seen)

    def testQueryUDPFallback(self):
        qname = dns.name.from_text('.')
        q = dns.message.make_query(qname, dns.rdatatype.DNSKEY)
        (_, tcp) = dns.query.udp_with_fallback(q, '8.8.8.8')
        self.assertTrue(tcp)

    def testQueryUDPFallbackWithSocket(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_s:
            udp_s.setblocking(0)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_s:
                tcp_s.connect(('8.8.8.8', 53))
                tcp_s.setblocking(0)
                qname = dns.name.from_text('.')
                q = dns.message.make_query(qname, dns.rdatatype.DNSKEY)
                (_, tcp) = dns.query.udp_with_fallback(q, '8.8.8.8',
                                                      udp_sock=udp_s,
                                                      tcp_sock=tcp_s)
                self.assertTrue(tcp)

    def testQueryUDPFallbackNoFallback(self):
        qname = dns.name.from_text('dns.google.')
        q = dns.message.make_query(qname, dns.rdatatype.A)
        (_, tcp) = dns.query.udp_with_fallback(q, '8.8.8.8')
        self.assertFalse(tcp)


axfr_zone = '''
$ORIGIN example.
$TTL 300
@ SOA ns1 root 1 7200 900 1209600 86400
@ NS ns1
@ NS ns2
ns1 A 10.0.0.1
ns2 A 10.0.0.1
'''

class AXFRNanoNameserver(Server):

    def handle(self, message, peer, connection_type):
        self.zone = dns.zone.from_text(axfr_zone, origin='example')
        self.origin = self.zone.origin
        items = []
        soa = self.zone.find_rrset(dns.name.empty, dns.rdatatype.SOA)
        response = dns.message.make_response(message)
        response.flags |= dns.flags.AA
        response.answer.append(soa)
        items.append(response)
        response = dns.message.make_response(message)
        response.question = []
        response.flags |= dns.flags.AA
        for (name, rdataset) in self.zone.iterate_rdatasets():
            if rdataset.rdtype == dns.rdatatype.SOA and \
               name == dns.name.empty:
                continue
            rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype,
                                    rdataset.covers)
            rrset.update(rdataset)
            response.answer.append(rrset)
        items.append(response)
        response = dns.message.make_response(message)
        response.question = []
        response.flags |= dns.flags.AA
        response.answer.append(soa)
        items.append(response)
        return items

ixfr_message = '''id 12345
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
example. 300 IN SOA ns1.example. root.example. 4 7200 900 1209600 86400
example. 300 IN SOA ns1.example. root.example. 2 7200 900 1209600 86400
deleted.example. 300 IN A 10.0.0.1
changed.example. 300 IN A 10.0.0.2
example. 300 IN SOA ns1.example. root.example. 3 7200 900 1209600 86400
changed.example. 300 IN A 10.0.0.4
added.example. 300 IN A 10.0.0.3
example. 300 SOA ns1.example. root.example. 3 7200 900 1209600 86400
example. 300 IN SOA ns1.example. root.example. 4 7200 900 1209600 86400
added2.example. 300 IN A 10.0.0.5
example. 300 IN SOA ns1.example. root.example. 4 7200 900 1209600 86400
'''

ixfr_trailing_junk = ixfr_message + 'junk.example. 300 IN A 10.0.0.6'

ixfr_up_to_date_message = '''id 12345
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
example. 300 IN SOA ns1.example. root.example. 2 7200 900 1209600 86400
'''

axfr_trailing_junk = '''id 12345
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN AXFR
;ANSWER
example. 300 IN SOA ns1.example. root.example. 3 7200 900 1209600 86400
added.example. 300 IN A 10.0.0.3
added2.example. 300 IN A 10.0.0.5
changed.example. 300 IN A 10.0.0.4
example. 300 IN SOA ns1.example. root.example. 3 7200 900 1209600 86400
junk.example. 300 IN A 10.0.0.6
'''

class IXFRNanoNameserver(Server):

    def __init__(self, response_text):
        super().__init__()
        self.response_text = response_text

    def handle(self, message, peer, connection_type):
        try:
            r = dns.message.from_text(self.response_text, one_rr_per_rrset=True)
            r.id = message.id
            return r
        except Exception:
            pass

@unittest.skipIf(not _nanonameserver_available,
                 "Internet and nanonameserver required")
class XfrTests(unittest.TestCase):

    def test_axfr(self):
        expected = dns.zone.from_text(axfr_zone, origin='example')
        with AXFRNanoNameserver() as ns:
            xfr = dns.query.xfr(ns.tcp_address[0], 'example',
                                port=ns.tcp_address[1])
            zone = dns.zone.from_xfr(xfr)
            self.assertEqual(zone, expected)

    def test_axfr_udp(self):
        def bad():
            with AXFRNanoNameserver() as ns:
                xfr = dns.query.xfr(ns.udp_address[0], 'example',
                                    port=ns.udp_address[1], use_udp=True)
                l = list(xfr)
        self.assertRaises(ValueError, bad)

    def test_axfr_bad_rcode(self):
        def bad():
            # We just use Server here as by default it will refuse.
            with Server() as ns:
                xfr = dns.query.xfr(ns.tcp_address[0], 'example',
                                    port=ns.tcp_address[1])
                l = list(xfr)
        self.assertRaises(dns.query.TransferError, bad)

    def test_axfr_trailing_junk(self):
        # we use the IXFR server here as it returns messages
        def bad():
            with IXFRNanoNameserver(axfr_trailing_junk) as ns:
                xfr = dns.query.xfr(ns.tcp_address[0], 'example',
                                    dns.rdatatype.AXFR,
                                    port=ns.tcp_address[1])
                l = list(xfr)
        self.assertRaises(dns.exception.FormError, bad)

    def test_ixfr_tcp(self):
        with IXFRNanoNameserver(ixfr_message) as ns:
            xfr = dns.query.xfr(ns.tcp_address[0], 'example',
                                dns.rdatatype.IXFR,
                                port=ns.tcp_address[1],
                                serial=2,
                                relativize=False)
            l = list(xfr)
            self.assertEqual(len(l), 1)
            expected = dns.message.from_text(ixfr_message,
                                             one_rr_per_rrset=True)
            expected.id = l[0].id
            self.assertEqual(l[0], expected)

    def test_ixfr_udp(self):
        with IXFRNanoNameserver(ixfr_message) as ns:
            xfr = dns.query.xfr(ns.udp_address[0], 'example',
                                dns.rdatatype.IXFR,
                                port=ns.udp_address[1],
                                serial=2,
                                relativize=False, use_udp=True)
            l = list(xfr)
            self.assertEqual(len(l), 1)
            expected = dns.message.from_text(ixfr_message,
                                             one_rr_per_rrset=True)
            expected.id = l[0].id
            self.assertEqual(l[0], expected)

    def test_ixfr_up_to_date(self):
        with IXFRNanoNameserver(ixfr_up_to_date_message) as ns:
            xfr = dns.query.xfr(ns.tcp_address[0], 'example',
                                dns.rdatatype.IXFR,
                                port=ns.tcp_address[1],
                                serial=2,
                                relativize=False)
            l = list(xfr)
            self.assertEqual(len(l), 1)
            expected = dns.message.from_text(ixfr_up_to_date_message,
                                             one_rr_per_rrset=True)
            expected.id = l[0].id
            print(expected)
            print(l[0])
            self.assertEqual(l[0], expected)

    def test_ixfr_trailing_junk(self):
        def bad():
            with IXFRNanoNameserver(ixfr_trailing_junk) as ns:
                xfr = dns.query.xfr(ns.tcp_address[0], 'example',
                                    dns.rdatatype.IXFR,
                                    port=ns.tcp_address[1],
                                    serial=2,
                                    relativize=False)
                l = list(xfr)
        self.assertRaises(dns.exception.FormError, bad)

    def test_ixfr_base_serial_mismatch(self):
        def bad():
            with IXFRNanoNameserver(ixfr_message) as ns:
                xfr = dns.query.xfr(ns.tcp_address[0], 'example',
                                    dns.rdatatype.IXFR,
                                    port=ns.tcp_address[1],
                                    serial=1,
                                    relativize=False)
                l = list(xfr)
        self.assertRaises(dns.exception.FormError, bad)
