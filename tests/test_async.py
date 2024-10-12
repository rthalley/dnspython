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
import random
import socket
import time
import unittest

import dns.asyncbackend
import dns.asyncquery
import dns.asyncresolver
import dns.message
import dns.name
import dns.query
import dns.quic
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import tests.util

# Some tests require TLS so skip those if it's not there.
ssl = dns.query.ssl
try:
    ssl.create_default_context()
    _ssl_available = True
except Exception:
    _ssl_available = False


# Look for systemd-resolved, as it does dangling CNAME responses incorrectly.
#
# Currently we simply check if the nameserver is 127.0.0.53.
_systemd_resolved_present = False
try:
    _resolver = dns.resolver.Resolver()
    if _resolver.nameservers == ["127.0.0.53"]:
        _systemd_resolved_present = True
except Exception:
    pass

# Docker too!  It not only has problems with dangling CNAME, but also says NXDOMAIN when
# it should say no error no data.
_is_docker = tests.util.is_docker()

query_addresses = []
family = socket.AF_UNSPEC
if tests.util.have_ipv4():
    query_addresses.append("8.8.8.8")
    family = socket.AF_INET
if tests.util.have_ipv6():
    have_v6 = True
    if family == socket.AF_INET:
        # we have both working, go back to UNSPEC
        family = socket.AF_UNSPEC
    else:
        # v6 only
        family = socket.AF_INET6
    query_addresses.append("2001:4860:4860::8888")

KNOWN_ANYCAST_DOH_RESOLVER_URLS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    # 'https://dns11.quad9.net/dns-query',
]

KNOWN_ANYCAST_DOH3_RESOLVER_URLS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]


class AsyncDetectionTests(unittest.TestCase):
    sniff_result = "asyncio"

    def async_run(self, afunc):
        return asyncio.run(afunc())

    def test_sniff(self):
        dns.asyncbackend._default_backend = None

        async def run():
            self.assertEqual(dns.asyncbackend.sniff(), self.sniff_result)

        self.async_run(run)

    def test_get_default_backend(self):
        dns.asyncbackend._default_backend = None

        async def run():
            backend = dns.asyncbackend.get_default_backend()
            self.assertEqual(backend.name(), self.sniff_result)

        self.async_run(run)


class NoSniffioAsyncDetectionTests(AsyncDetectionTests):
    expect_raise = False

    def setUp(self):
        dns.asyncbackend._no_sniffio = True

    def tearDown(self):
        dns.asyncbackend._no_sniffio = False

    def test_sniff(self):
        dns.asyncbackend._default_backend = None
        if self.expect_raise:

            async def abad():
                dns.asyncbackend.sniff()

            def bad():
                self.async_run(abad)

            self.assertRaises(dns.asyncbackend.AsyncLibraryNotFoundError, bad)
        else:
            super().test_sniff()

    def test_get_default_backend(self):
        dns.asyncbackend._default_backend = None
        if self.expect_raise:

            async def abad():
                dns.asyncbackend.get_default_backend()

            def bad():
                self.async_run(abad)

            self.assertRaises(dns.asyncbackend.AsyncLibraryNotFoundError, bad)
        else:
            super().test_get_default_backend()


class MiscBackend(unittest.TestCase):
    def test_sniff_without_run_loop(self):
        dns.asyncbackend._default_backend = None

        def bad():
            dns.asyncbackend.sniff()

        self.assertRaises(dns.asyncbackend.AsyncLibraryNotFoundError, bad)

    def test_bogus_backend(self):
        def bad():
            dns.asyncbackend.get_backend("bogus")

        self.assertRaises(NotImplementedError, bad)


class MiscQuery(unittest.TestCase):
    def test_source_tuple(self):
        t = dns.asyncquery._source_tuple(socket.AF_INET, None, 0)
        self.assertEqual(t, None)
        t = dns.asyncquery._source_tuple(socket.AF_INET6, None, 0)
        self.assertEqual(t, None)
        t = dns.asyncquery._source_tuple(socket.AF_INET, "1.2.3.4", 53)
        self.assertEqual(t, ("1.2.3.4", 53))
        t = dns.asyncquery._source_tuple(socket.AF_INET6, "1::2", 53)
        self.assertEqual(t, ("1::2", 53))
        t = dns.asyncquery._source_tuple(socket.AF_INET, None, 53)
        self.assertEqual(t, ("0.0.0.0", 53))
        t = dns.asyncquery._source_tuple(socket.AF_INET6, None, 53)
        self.assertEqual(t, ("::", 53))


@unittest.skipIf(not tests.util.is_internet_reachable(), "Internet not reachable")
class AsyncTests(unittest.TestCase):
    def setUp(self):
        self.backend = dns.asyncbackend.set_default_backend("asyncio")

    def async_run(self, afunc):
        return asyncio.run(afunc())

    @tests.util.retry_on_timeout
    def testResolve(self):
        async def run():
            answer = await dns.asyncresolver.resolve("dns.google.", "A")
            return set([rdata.address for rdata in answer])

        seen = self.async_run(run)
        self.assertTrue("8.8.8.8" in seen)
        self.assertTrue("8.8.4.4" in seen)

    @tests.util.retry_on_timeout
    def testResolveAddress(self):
        async def run():
            return await dns.asyncresolver.resolve_address("8.8.8.8")

        answer = self.async_run(run)
        dnsgoogle = dns.name.from_text("dns.google.")
        self.assertEqual(answer[0].target, dnsgoogle)

    @tests.util.retry_on_timeout
    def testResolveName(self):
        async def run1():
            return await dns.asyncresolver.resolve_name("dns.google.")

        answers = self.async_run(run1)
        seen = set(answers.addresses())
        self.assertEqual(len(seen), 4)
        self.assertIn("8.8.8.8", seen)
        self.assertIn("8.8.4.4", seen)
        self.assertIn("2001:4860:4860::8844", seen)
        self.assertIn("2001:4860:4860::8888", seen)

        async def run2():
            return await dns.asyncresolver.resolve_name("dns.google.", socket.AF_INET)

        answers = self.async_run(run2)
        seen = set(answers.addresses())
        self.assertEqual(len(seen), 2)
        self.assertIn("8.8.8.8", seen)
        self.assertIn("8.8.4.4", seen)

        async def run3():
            return await dns.asyncresolver.resolve_name("dns.google.", socket.AF_INET6)

        answers = self.async_run(run3)
        seen = set(answers.addresses())
        self.assertEqual(len(seen), 2)
        self.assertIn("2001:4860:4860::8844", seen)
        self.assertIn("2001:4860:4860::8888", seen)

        async def run4():
            await dns.asyncresolver.resolve_name("nxdomain.dnspython.org")

        with self.assertRaises(dns.resolver.NXDOMAIN):
            self.async_run(run4)

        async def run5():
            await dns.asyncresolver.resolve_name(
                dns.reversename.from_address("8.8.8.8")
            )

        if not _is_docker:
            # docker returns NXDOMAIN!
            with self.assertRaises(dns.resolver.NoAnswer):
                self.async_run(run5)

    @tests.util.retry_on_timeout
    def testCanonicalNameNoCNAME(self):
        cname = dns.name.from_text("www.google.com")

        async def run():
            return await dns.asyncresolver.canonical_name("www.google.com")

        self.assertEqual(self.async_run(run), cname)

    @tests.util.retry_on_timeout
    def testCanonicalNameCNAME(self):
        name = dns.name.from_text("www.dnspython.org")
        cname = dns.name.from_text("dmfrjf4ips8xa.cloudfront.net")

        async def run():
            return await dns.asyncresolver.canonical_name(name)

        self.assertEqual(self.async_run(run), cname)

    @unittest.skipIf(
        _systemd_resolved_present or _is_docker, "systemd-resolved or docker in use"
    )
    @tests.util.retry_on_timeout
    def testCanonicalNameDangling(self):
        name = dns.name.from_text("dangling-cname.dnspython.org")
        cname = dns.name.from_text("dangling-target.dnspython.org")

        async def run():
            return await dns.asyncresolver.canonical_name(name)

        self.assertEqual(self.async_run(run), cname)

    @tests.util.retry_on_timeout
    def testZoneForName1(self):
        async def run():
            name = dns.name.from_text("www.dnspython.org.")
            return await dns.asyncresolver.zone_for_name(name)

        ezname = dns.name.from_text("dnspython.org.")
        zname = self.async_run(run)
        self.assertEqual(zname, ezname)

    @tests.util.retry_on_timeout
    def testZoneForName2(self):
        async def run():
            name = dns.name.from_text("a.b.www.dnspython.org.")
            return await dns.asyncresolver.zone_for_name(name)

        ezname = dns.name.from_text("dnspython.org.")
        zname = self.async_run(run)
        self.assertEqual(zname, ezname)

    @tests.util.retry_on_timeout
    def testZoneForName3(self):
        async def run():
            name = dns.name.from_text("dnspython.org.")
            return await dns.asyncresolver.zone_for_name(name)

        ezname = dns.name.from_text("dnspython.org.")
        zname = self.async_run(run)
        self.assertEqual(zname, ezname)

    def testZoneForName4(self):
        def bad():
            name = dns.name.from_text("dnspython.org", None)

            async def run():
                return await dns.asyncresolver.zone_for_name(name)

            self.async_run(run)

        self.assertRaises(dns.resolver.NotAbsolute, bad)

    @tests.util.retry_on_timeout
    def testQueryUDP(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.udp(q, address, timeout=2)

            response = self.async_run(run)
            rrs = response.get_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
            )
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

    @tests.util.retry_on_timeout
    def testQueryUDPWithSocket(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                async with await self.backend.make_socket(
                    dns.inet.af_for_address(address),
                    socket.SOCK_DGRAM,
                    0,
                    None,
                    None,
                ) as s:
                    q = dns.message.make_query(qname, dns.rdatatype.A)
                    return await dns.asyncquery.udp(q, address, sock=s, timeout=2)

            response = self.async_run(run)
            rrs = response.get_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
            )
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

    @tests.util.retry_on_timeout
    def testQueryTCP(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.tcp(q, address, timeout=2)

            response = self.async_run(run)
            rrs = response.get_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
            )
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

    @tests.util.retry_on_timeout
    def testQueryTCPWithSocket(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                async with await self.backend.make_socket(
                    dns.inet.af_for_address(address),
                    socket.SOCK_STREAM,
                    0,
                    None,
                    (address, 53),
                    2,
                ) as s:
                    # for basic coverage
                    await s.getsockname()
                    q = dns.message.make_query(qname, dns.rdatatype.A)
                    return await dns.asyncquery.tcp(q, address, sock=s, timeout=2)

            response = self.async_run(run)
            rrs = response.get_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
            )
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

    @unittest.skipIf(not _ssl_available, "SSL not available")
    @tests.util.retry_on_timeout
    def testQueryTLS(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.tls(q, address, timeout=2)

            response = self.async_run(run)
            rrs = response.get_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
            )
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

    @unittest.skipIf(not _ssl_available, "SSL not available")
    @tests.util.retry_on_timeout
    def testQueryTLSWithContext(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = True
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.tls(
                    q, address, timeout=2, ssl_context=ssl_context
                )

            response = self.async_run(run)
            rrs = response.get_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
            )
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

    @unittest.skipIf(not _ssl_available, "SSL not available")
    @tests.util.retry_on_timeout
    def testQueryTLSWithSocket(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                async with await self.backend.make_socket(
                    dns.inet.af_for_address(address),
                    socket.SOCK_STREAM,
                    0,
                    None,
                    (address, 853),
                    2,
                    ssl_context,
                    None,
                ) as s:
                    # for basic coverage
                    await s.getsockname()
                    q = dns.message.make_query(qname, dns.rdatatype.A)
                    return await dns.asyncquery.tls(q, "8.8.8.8", sock=s, timeout=2)

            response = self.async_run(run)
            rrs = response.get_rrset(
                response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
            )
            self.assertTrue(rrs is not None)
            seen = set([rdata.address for rdata in rrs])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

    @tests.util.retry_on_timeout
    def testQueryUDPFallback(self):
        for address in query_addresses:
            qname = dns.name.from_text(".")

            async def run():
                q = dns.message.make_query(qname, dns.rdatatype.DNSKEY)
                return await dns.asyncquery.udp_with_fallback(q, address, timeout=4)

            (_, tcp) = self.async_run(run)
            self.assertTrue(tcp)

    @tests.util.retry_on_timeout
    def testQueryUDPFallbackNoFallback(self):
        for address in query_addresses:
            qname = dns.name.from_text("dns.google.")

            async def run():
                q = dns.message.make_query(qname, dns.rdatatype.A)
                return await dns.asyncquery.udp_with_fallback(q, address, timeout=2)

            (_, tcp) = self.async_run(run)
            self.assertFalse(tcp)

    @tests.util.retry_on_timeout
    def testUDPReceiveQuery(self):
        async def run():
            async with await self.backend.make_socket(
                socket.AF_INET, socket.SOCK_DGRAM, source=("127.0.0.1", 0)
            ) as listener:
                listener_address = await listener.getsockname()
                async with await self.backend.make_socket(
                    socket.AF_INET, socket.SOCK_DGRAM, source=("127.0.0.1", 0)
                ) as sender:
                    sender_address = await sender.getsockname()
                    q = dns.message.make_query("dns.google", dns.rdatatype.A)
                    await dns.asyncquery.send_udp(sender, q, listener_address)
                    expiration = time.time() + 2
                    (_, _, recv_address) = await dns.asyncquery.receive_udp(
                        listener, expiration=expiration
                    )
                    return (sender_address, recv_address)

        (sender_address, recv_address) = self.async_run(run)
        self.assertEqual(sender_address, recv_address)

    def testUDPReceiveTimeout(self):
        async def arun():
            async with await self.backend.make_socket(
                socket.AF_INET, socket.SOCK_DGRAM, 0, ("127.0.0.1", 0)
            ) as s:
                try:
                    # for basic coverage
                    await s.getpeername()
                except Exception:
                    # we expect failure as we haven't connected the socket
                    pass
                await s.recvfrom(1000, 0.05)

        def run():
            self.async_run(arun)

        self.assertRaises(dns.exception.Timeout, run)

    @unittest.skipIf(not dns.query._have_httpx, "httpx not available")
    @tests.util.retry_on_timeout
    def testDOHGetRequest(self):
        async def run():
            nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
            q = dns.message.make_query("example.com.", dns.rdatatype.A)
            r = await dns.asyncquery.https(
                q, nameserver_url, post=False, timeout=4, family=family
            )
            self.assertTrue(q.is_response(r))

        self.async_run(run)

    @unittest.skipIf(not dns.query._have_httpx, "httpx not available")
    @tests.util.retry_on_timeout
    def testDOHPostRequest(self):
        async def run():
            nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
            q = dns.message.make_query("example.com.", dns.rdatatype.A)
            r = await dns.asyncquery.https(
                q, nameserver_url, post=True, timeout=4, family=family
            )
            self.assertTrue(q.is_response(r))

        self.async_run(run)

    @unittest.skipIf(not dns.quic.have_quic, "aioquic not available")
    @tests.util.retry_on_timeout
    def testDoH3GetRequest(self):
        async def run():
            nameserver_url = random.choice(KNOWN_ANYCAST_DOH3_RESOLVER_URLS)
            q = dns.message.make_query("dns.google.", dns.rdatatype.A)
            r = await dns.asyncquery.https(
                q,
                nameserver_url,
                post=False,
                timeout=4,
                family=family,
                http_version=dns.asyncquery.HTTPVersion.H3,
            )
            self.assertTrue(q.is_response(r))

        self.async_run(run)

    @unittest.skipIf(not dns.quic.have_quic, "aioquic not available")
    @tests.util.retry_on_timeout
    def TestDoH3PostRequest(self):
        async def run():
            nameserver_url = random.choice(KNOWN_ANYCAST_DOH3_RESOLVER_URLS)
            q = dns.message.make_query("dns.google.", dns.rdatatype.A)
            r = await dns.asyncquery.https(
                q,
                nameserver_url,
                post=True,
                timeout=4,
                family=family,
                http_version=dns.asyncquery.HTTPVersion.H3,
            )
            self.assertTrue(q.is_response(r))

        self.async_run(run)

    @unittest.skipIf(not dns.quic.have_quic, "aioquic not available")
    @tests.util.retry_on_timeout
    def TestDoH3QueryIP(self):
        async def run():
            nameserver_ip = "8.8.8.8"
            q = dns.message.make_query("example.com.", dns.rdatatype.A)
            r = dns.asyncquery.https(
                q,
                nameserver_ip,
                post=False,
                timeout=4,
                http_version=dns.asyncquery.HTTPVersion.H3,
            )
            self.assertTrue(q.is_response(r))

        self.async_run(run)

    @unittest.skipIf(not dns.query._have_httpx, "httpx not available")
    @tests.util.retry_on_timeout
    def testResolverDOH(self):
        async def run():
            res = dns.asyncresolver.Resolver(configure=False)
            res.nameservers = ["https://dns.google/dns-query"]
            answer = await res.resolve("dns.google", "A", backend=self.backend)
            seen = set([rdata.address for rdata in answer])
            self.assertTrue("8.8.8.8" in seen)
            self.assertTrue("8.8.4.4" in seen)

        self.async_run(run)

    @unittest.skipIf(not tests.util.have_ipv4(), "IPv4 not reachable")
    @tests.util.retry_on_timeout
    def testResolveAtAddress(self):
        async def run():
            answer = await dns.asyncresolver.resolve_at("8.8.8.8", "dns.google.", "A")
            seen = set([rdata.address for rdata in answer])
            self.assertIn("8.8.8.8", seen)
            self.assertIn("8.8.4.4", seen)

        self.async_run(run)

    @unittest.skipIf(not tests.util.have_ipv4(), "IPv4 not reachable")
    @tests.util.retry_on_timeout
    def testResolveAtName(self):
        async def run():
            answer = await dns.asyncresolver.resolve_at(
                "dns.google", "dns.google.", "A", family=socket.AF_INET
            )
            seen = set([rdata.address for rdata in answer])
            self.assertIn("8.8.8.8", seen)
            self.assertIn("8.8.4.4", seen)

        self.async_run(run)

    def testSleep(self):
        async def run():
            before = time.time()
            await self.backend.sleep(0.1)
            after = time.time()
            self.assertTrue(after - before >= 0.1)

        self.async_run(run)


@unittest.skipIf(not tests.util.is_internet_reachable(), "Internet not reachable")
class AsyncioOnlyTests(unittest.TestCase):
    def setUp(self):
        self.backend = dns.asyncbackend.set_default_backend("asyncio")

    def async_run(self, afunc):
        return asyncio.run(afunc())

    @tests.util.retry_on_timeout
    def testUseAfterTimeout(self):
        # Test #843 fix.
        async def run():
            qname = dns.name.from_text("dns.google")
            query = dns.message.make_query(qname, "A")
            sock = await self.backend.make_socket(socket.AF_INET, socket.SOCK_DGRAM)
            async with sock:
                # First do something that will definitely timeout.
                try:
                    response = await dns.asyncquery.udp(
                        query, "8.8.8.8", timeout=0.0001, sock=sock
                    )
                except dns.exception.Timeout:
                    pass
                except Exception:
                    self.assertTrue(False)
                # Now try to reuse the socket with a reasonable timeout.
                try:
                    response = await dns.asyncquery.udp(
                        query, "8.8.8.8", timeout=5, sock=sock
                    )
                    rrs = response.get_rrset(
                        response.answer, qname, dns.rdataclass.IN, dns.rdatatype.A
                    )
                    self.assertTrue(rrs is not None)
                    seen = set([rdata.address for rdata in rrs])
                    self.assertTrue("8.8.8.8" in seen)
                    self.assertTrue("8.8.4.4" in seen)
                except Exception:
                    self.assertTrue(False)

        self.async_run(run)


try:
    import sniffio
    import trio

    class TrioAsyncDetectionTests(AsyncDetectionTests):
        sniff_result = "trio"

        def async_run(self, afunc):
            return trio.run(afunc)

    class TrioNoSniffioAsyncDetectionTests(NoSniffioAsyncDetectionTests):
        expect_raise = True

        def async_run(self, afunc):
            return trio.run(afunc)

    class TrioAsyncTests(AsyncTests):
        def setUp(self):
            self.backend = dns.asyncbackend.set_default_backend("trio")

        def async_run(self, afunc):
            return trio.run(afunc)

except ImportError:
    pass


class MockSock:
    def __init__(self, wire1, from1, wire2, from2):
        self.family = socket.AF_INET
        self.first_time = True
        self.wire1 = wire1
        self.from1 = from1
        self.wire2 = wire2
        self.from2 = from2

    async def sendto(self, data, where, timeout):
        return len(data)

    async def recvfrom(self, bufsize, expiration):
        if self.first_time:
            self.first_time = False
            return self.wire1, self.from1
        else:
            return self.wire2, self.from2


class IgnoreErrors(unittest.TestCase):
    def setUp(self):
        self.q = dns.message.make_query("example.", "A")
        self.good_r = dns.message.make_response(self.q)
        self.good_r.set_rcode(dns.rcode.NXDOMAIN)
        self.good_r_wire = self.good_r.to_wire()
        dns.asyncbackend.set_default_backend("asyncio")

    def async_run(self, afunc):
        return asyncio.run(afunc())

    async def mock_receive(
        self,
        wire1,
        from1,
        wire2,
        from2,
        ignore_unexpected=True,
        ignore_errors=True,
        raise_on_truncation=False,
        good_r=None,
    ):
        if good_r is None:
            good_r = self.good_r
        s = MockSock(wire1, from1, wire2, from2)
        (r, when, _) = await dns.asyncquery.receive_udp(
            s,
            ("127.0.0.1", 53),
            time.time() + 2,
            ignore_unexpected=ignore_unexpected,
            ignore_errors=ignore_errors,
            raise_on_truncation=raise_on_truncation,
            query=self.q,
        )
        self.assertEqual(r, good_r)

    def test_good_mock(self):
        async def run():
            await self.mock_receive(self.good_r_wire, ("127.0.0.1", 53), None, None)

        self.async_run(run)

    def test_bad_address(self):
        async def run():
            await self.mock_receive(
                self.good_r_wire, ("127.0.0.2", 53), self.good_r_wire, ("127.0.0.1", 53)
            )

        self.async_run(run)

    def test_bad_address_not_ignored(self):
        async def abad():
            await self.mock_receive(
                self.good_r_wire,
                ("127.0.0.2", 53),
                self.good_r_wire,
                ("127.0.0.1", 53),
                ignore_unexpected=False,
            )

        def bad():
            self.async_run(abad)

        self.assertRaises(dns.query.UnexpectedSource, bad)

    def test_not_response_not_ignored_udp_level(self):
        async def abad():
            bad_r = dns.message.make_response(self.q)
            bad_r.id += 1
            bad_r_wire = bad_r.to_wire()
            s = MockSock(
                bad_r_wire, ("127.0.0.1", 53), self.good_r_wire, ("127.0.0.1", 53)
            )
            await dns.asyncquery.udp(self.good_r, "127.0.0.1", sock=s)

        def bad():
            self.async_run(abad)

        self.assertRaises(dns.query.BadResponse, bad)

    def test_bad_id(self):
        async def run():
            bad_r = dns.message.make_response(self.q)
            bad_r.id += 1
            bad_r_wire = bad_r.to_wire()
            await self.mock_receive(
                bad_r_wire, ("127.0.0.1", 53), self.good_r_wire, ("127.0.0.1", 53)
            )

        self.async_run(run)

    def test_bad_id_not_ignored(self):
        bad_r = dns.message.make_response(self.q)
        bad_r.id += 1
        bad_r_wire = bad_r.to_wire()

        async def abad():
            (r, wire) = await self.mock_receive(
                bad_r_wire,
                ("127.0.0.1", 53),
                self.good_r_wire,
                ("127.0.0.1", 53),
                ignore_errors=False,
            )

        def bad():
            self.async_run(abad)

        self.assertRaises(AssertionError, bad)

    def test_bad_wire(self):
        async def run():
            bad_r = dns.message.make_response(self.q)
            bad_r.id += 1
            bad_r_wire = bad_r.to_wire()
            await self.mock_receive(
                bad_r_wire[:10], ("127.0.0.1", 53), self.good_r_wire, ("127.0.0.1", 53)
            )

        self.async_run(run)

    def test_good_wire_with_truncation_flag_and_no_truncation_raise(self):
        async def run():
            tc_r = dns.message.make_response(self.q)
            tc_r.flags |= dns.flags.TC
            tc_r_wire = tc_r.to_wire()
            await self.mock_receive(
                tc_r_wire, ("127.0.0.1", 53), None, None, good_r=tc_r
            )

        self.async_run(run)

    def test_good_wire_with_truncation_flag_and_truncation_raise(self):
        async def agood():
            tc_r = dns.message.make_response(self.q)
            tc_r.flags |= dns.flags.TC
            tc_r_wire = tc_r.to_wire()
            await self.mock_receive(
                tc_r_wire, ("127.0.0.1", 53), None, None, raise_on_truncation=True
            )

        def good():
            self.async_run(agood)

        self.assertRaises(dns.message.Truncated, good)

    def test_wrong_id_wire_with_truncation_flag_and_no_truncation_raise(self):
        async def run():
            bad_r = dns.message.make_response(self.q)
            bad_r.id += 1
            bad_r.flags |= dns.flags.TC
            bad_r_wire = bad_r.to_wire()
            await self.mock_receive(
                bad_r_wire, ("127.0.0.1", 53), self.good_r_wire, ("127.0.0.1", 53)
            )

        self.async_run(run)

    def test_wrong_id_wire_with_truncation_flag_and_truncation_raise(self):
        async def run():
            bad_r = dns.message.make_response(self.q)
            bad_r.id += 1
            bad_r.flags |= dns.flags.TC
            bad_r_wire = bad_r.to_wire()
            await self.mock_receive(
                bad_r_wire,
                ("127.0.0.1", 53),
                self.good_r_wire,
                ("127.0.0.1", 53),
                raise_on_truncation=True,
            )

        self.async_run(run)

    def test_bad_wire_not_ignored(self):
        bad_r = dns.message.make_response(self.q)
        bad_r.id += 1
        bad_r_wire = bad_r.to_wire()

        async def abad():
            await self.mock_receive(
                bad_r_wire[:10],
                ("127.0.0.1", 53),
                self.good_r_wire,
                ("127.0.0.1", 53),
                ignore_errors=False,
            )

        def bad():
            self.async_run(abad)

        self.assertRaises(dns.message.ShortHeader, bad)

    def test_trailing_wire(self):
        async def run():
            wire = self.good_r_wire + b"abcd"
            await self.mock_receive(
                wire, ("127.0.0.1", 53), self.good_r_wire, ("127.0.0.1", 53)
            )

        self.async_run(run)

    def test_trailing_wire_not_ignored(self):
        wire = self.good_r_wire + b"abcd"

        async def abad():
            await self.mock_receive(
                wire,
                ("127.0.0.1", 53),
                self.good_r_wire,
                ("127.0.0.1", 53),
                ignore_errors=False,
            )

        def bad():
            self.async_run(abad)

        self.assertRaises(dns.message.TrailingJunk, bad)
