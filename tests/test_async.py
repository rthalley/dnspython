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

import asyncio
import socket
import unittest

import dns.asyncbackend
import dns.asyncquery
import dns.asyncresolver
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver


# Some tests require TLS so skip those if it's not there.
from dns.query import ssl
try:
    ssl.create_default_context()
    _ssl_available = True
except Exception:
    _ssl_available = False


# Some tests require the internet to be available to run, so let's
# skip those if it's not there.
_network_available = True
try:
    socket.gethostbyname('dnspython.org')
except socket.gaierror:
    _network_available = False


@unittest.skipIf(not _network_available, "Internet not reachable")
class AsyncTests(unittest.TestCase):

    def setUp(self):
        self.backend = dns.asyncbackend.set_default_backend('asyncio')

    def async_run(self, afunc):
        try:
            runner = asyncio.run
        except AttributeError:
            def old_runner(awaitable):
                loop = asyncio.get_event_loop()
                return loop.run_until_complete(awaitable)
            runner = old_runner
        return runner(afunc())

    def testResolve(self):
        async def run():
            answer = await dns.asyncresolver.resolve('dns.google.', 'A')
            return set([rdata.address for rdata in answer])
        seen = self.async_run(run)
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    def testResolveAddress(self):
        async def run():
            return await dns.asyncresolver.resolve_address('8.8.8.8')
        answer = self.async_run(run)
        dnsgoogle = dns.name.from_text('dns.google.')
        self.assertEqual(answer[0].target, dnsgoogle)

    def testZoneForName1(self):
        async def run():
            name = dns.name.from_text('www.dnspython.org.')
            return await dns.asyncresolver.zone_for_name(name)
        ezname = dns.name.from_text('dnspython.org.')
        zname = self.async_run(run)
        self.assertEqual(zname, ezname)

    def testZoneForName2(self):
        async def run():
            name = dns.name.from_text('a.b.www.dnspython.org.')
            return await dns.asyncresolver.zone_for_name(name)
        ezname = dns.name.from_text('dnspython.org.')
        zname = self.async_run(run)
        self.assertEqual(zname, ezname)

    def testZoneForName3(self):
        async def run():
            name = dns.name.from_text('dnspython.org.')
            return await dns.asyncresolver.zone_for_name(name)
        ezname = dns.name.from_text('dnspython.org.')
        zname = self.async_run(run)
        self.assertEqual(zname, ezname)

    def testZoneForName4(self):
        def bad():
            name = dns.name.from_text('dnspython.org', None)
            async def run():
                return await dns.asyncresolver.zone_for_name(name)
            self.async_run(run)
        self.assertRaises(dns.resolver.NotAbsolute, bad)

    def testQueryUDP(self):
        qname = dns.name.from_text('dns.google.')
        async def run():
            q = dns.message.make_query(qname, dns.rdatatype.A)
            return await dns.asyncquery.udp(q, '8.8.8.8')
        response = self.async_run(run)
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    def testQueryUDPWithSocket(self):
        qname = dns.name.from_text('dns.google.')
        async def run():
            async with await self.backend.make_socket(socket.AF_INET,
                                                      socket.SOCK_DGRAM) as s:
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.udp(q, '8.8.8.8', sock=s)
        response = self.async_run(run)
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    def testQueryTCP(self):
        qname = dns.name.from_text('dns.google.')
        async def run():
            q = dns.message.make_query(qname, dns.rdatatype.A)
            return await dns.asyncquery.tcp(q, '8.8.8.8')
        response = self.async_run(run)
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    def testQueryTCPWithSocket(self):
        qname = dns.name.from_text('dns.google.')
        async def run():
            async with await self.backend.make_socket(socket.AF_INET,
                                                      socket.SOCK_STREAM, 0,
                                                      None,
                                                      ('8.8.8.8', 53)) as s:
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.tcp(q, '8.8.8.8', sock=s)
        response = self.async_run(run)
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    @unittest.skipIf(not _ssl_available, "SSL not available")
    def testQueryTLS(self):
        qname = dns.name.from_text('dns.google.')
        async def run():
            q = dns.message.make_query(qname, dns.rdatatype.A)
            return await dns.asyncquery.tls(q, '8.8.8.8')
        response = self.async_run(run)
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    @unittest.skipIf(not _ssl_available, "SSL not available")
    def testQueryTLSWithSocket(self):
        qname = dns.name.from_text('dns.google.')
        async def run():
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            async with await self.backend.make_socket(socket.AF_INET,
                                                      socket.SOCK_STREAM, 0,
                                                      None,
                                                      ('8.8.8.8', 853), None,
                                                      ssl_context, None) as s:
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.tls(q, '8.8.8.8', sock=s)
        response = self.async_run(run)
        rrs = response.get_rrset(response.answer, qname,
                                 dns.rdataclass.IN, dns.rdatatype.A)
        self.assertTrue(rrs is not None)
        seen = set([rdata.address for rdata in rrs])
        self.assertTrue('8.8.8.8' in seen)
        self.assertTrue('8.8.4.4' in seen)

    def testQueryUDPFallback(self):
        qname = dns.name.from_text('.')
        async def run():
            q = dns.message.make_query(qname, dns.rdatatype.DNSKEY)
            return await dns.asyncquery.udp_with_fallback(q, '8.8.8.8')
        (_, tcp) = self.async_run(run)
        self.assertTrue(tcp)

    def testQueryUDPFallbackNoFallback(self):
        qname = dns.name.from_text('dns.google.')
        async def run():
            q = dns.message.make_query(qname, dns.rdatatype.A)
            return await dns.asyncquery.udp_with_fallback(q, '8.8.8.8')
        (_, tcp) = self.async_run(run)
        self.assertFalse(tcp)

try:
    import trio

    class TrioAsyncTests(AsyncTests):
        def setUp(self):
            self.backend = dns.asyncbackend.set_default_backend('trio')

        def async_run(self, afunc):
            return trio.run(afunc)
except ImportError:
    pass

try:
    import curio

    class CurioAsyncTests(AsyncTests):
        def setUp(self):
            self.backend = dns.asyncbackend.set_default_backend('curio')

        def async_run(self, afunc):
            return curio.run(afunc)
except ImportError:
    pass
