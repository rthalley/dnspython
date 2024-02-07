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
import random
import socket
import unittest

try:
    import ssl

    _have_ssl = True
except Exception:
    _have_ssl = False

import dns.edns
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

if dns.query._have_httpx:
    import httpx

import tests.util

resolver_v4_addresses = []
resolver_v6_addresses = []
family = socket.AF_UNSPEC
if tests.util.have_ipv4():
    resolver_v4_addresses = [
        "1.1.1.1",
        "8.8.8.8",
        # '9.9.9.9',
    ]
    family = socket.AF_INET
if tests.util.have_ipv6():
    resolver_v6_addresses = [
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
        # '2620:fe::fe',
    ]
    if family == socket.AF_INET:
        # we have both working, go back to UNSPEC
        family = socket.AF_UNSPEC
    else:
        # v6 only
        family = socket.AF_INET6

KNOWN_ANYCAST_DOH_RESOLVER_URLS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    # 'https://dns11.quad9.net/dns-query',
]

KNOWN_PAD_AWARE_DOH_RESOLVER_URLS = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
]


@unittest.skipUnless(
    dns.query._have_httpx and tests.util.is_internet_reachable() and _have_ssl,
    "Python httpx cannot be imported; no DNS over HTTPS (DOH)",
)
class DNSOverHTTPSTestCaseHttpx(unittest.TestCase):
    def setUp(self):
        self.session = httpx.Client(http1=True, http2=True, verify=True)

    def tearDown(self):
        self.session.close()

    def test_get_request(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query("example.com.", dns.rdatatype.A)
        r = dns.query.https(
            q,
            nameserver_url,
            session=self.session,
            post=False,
            timeout=4,
            family=family,
        )
        self.assertTrue(q.is_response(r))

    def test_post_request(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query("example.com.", dns.rdatatype.A)
        r = dns.query.https(
            q,
            nameserver_url,
            session=self.session,
            post=True,
            timeout=4,
            family=family,
        )
        self.assertTrue(q.is_response(r))

    def test_build_url_from_ip(self):
        self.assertTrue(resolver_v4_addresses or resolver_v6_addresses)
        if resolver_v4_addresses:
            nameserver_ip = random.choice(resolver_v4_addresses)
            q = dns.message.make_query("example.com.", dns.rdatatype.A)
            # For some reason Google's DNS over HTTPS fails when you POST to
            # https://8.8.8.8/dns-query
            # So we're just going to do GET requests here
            r = dns.query.https(
                q, nameserver_ip, session=self.session, post=False, timeout=4
            )

            self.assertTrue(q.is_response(r))
        if resolver_v6_addresses:
            nameserver_ip = random.choice(resolver_v6_addresses)
            q = dns.message.make_query("example.com.", dns.rdatatype.A)
            r = dns.query.https(
                q, nameserver_ip, session=self.session, post=False, timeout=4
            )
            self.assertTrue(q.is_response(r))

    # This test is temporarily disabled as there's an expired certificate issue on one
    # of the servers, so it fails on the part that is supposed to succeed (2023-07-15).

    # def test_bootstrap_address_fails(self):
    #     # We test this to see if v4 is available
    #     if resolver_v4_addresses:
    #         ip = "185.228.168.168"
    #         invalid_tls_url = "https://{}/doh/family-filter/".format(ip)
    #         valid_tls_url = "https://doh.cleanbrowsing.org/doh/family-filter/"
    #         q = dns.message.make_query("example.com.", dns.rdatatype.A)
    #         # make sure CleanBrowsing's IP address will fail TLS certificate
    #         # check.
    #         with self.assertRaises(httpx.ConnectError):
    #             dns.query.https(q, invalid_tls_url, session=self.session, timeout=4)
    #         # And if we don't mangle the URL, it should work.
    #         r = dns.query.https(
    #             q,
    #             valid_tls_url,
    #             session=self.session,
    #             bootstrap_address=ip,
    #             timeout=4,
    #         )
    #         self.assertTrue(q.is_response(r))

    def test_new_session(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query("example.com.", dns.rdatatype.A)
        r = dns.query.https(q, nameserver_url, timeout=4)
        self.assertTrue(q.is_response(r))

    def test_resolver(self):
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = ["https://dns.google/dns-query"]
        answer = res.resolve("dns.google", "A")
        seen = set([rdata.address for rdata in answer])
        self.assertTrue("8.8.8.8" in seen)
        self.assertTrue("8.8.4.4" in seen)

    def test_padded_get(self):
        nameserver_url = random.choice(KNOWN_PAD_AWARE_DOH_RESOLVER_URLS)
        q = dns.message.make_query("example.com.", dns.rdatatype.A, use_edns=0, pad=128)
        r = dns.query.https(
            q, nameserver_url, session=self.session, post=False, timeout=4
        )
        self.assertTrue(q.is_response(r))
        # the response should have a padding option
        self.assertIsNotNone(r.opt)
        has_pad = False
        for o in r.opt[0].options:
            if o.otype == dns.edns.OptionType.PADDING:
                has_pad = True
        self.assertTrue(has_pad)


if __name__ == "__main__":
    unittest.main()
