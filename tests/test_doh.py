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

import unittest
import random

import dns.query
import dns.rdatatype
import dns.message

KNOWN_ANYCAST_DOH_RESOLVER_IPS = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
KNOWN_ANYCAST_DOH_RESOLVER_URLS = ['https://cloudflare-dns.com/dns-query',
                                   'https://dns.google/dns-query',
                                   'https://dns11.quad9.net/dns-query']

class DNSOverHTTPSTestCase(unittest.TestCase):
    nameserver_ip = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_IPS)

    def test_get_request(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        r = dns.query.https(q, nameserver_url, post=False)
        self.assertTrue(q.is_response(r))

    def test_post_request(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        r = dns.query.https(q, nameserver_url, post=True)
        self.assertTrue(q.is_response(r))

    def test_build_url_from_ip(self):
        nameserver_ip = '8.8.8.8' #random.choice(KNOWN_ANYCAST_DOH_RESOLVER_IPS)
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        # For some reason Google's DNS over HTTPS fails when you POST to https://8.8.8.8/dns-query
        # So we're just going to do the GET request
        r = dns.query.https(q, nameserver_ip, post=False)
        self.assertTrue(q.is_response(r))

    def test_custom_path(self):
        cleanbrowsing_ip = '185.228.168.168'
        cleanbrowsing_path = '/doh/security-filter/'
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        r = dns.query.https(q, cleanbrowsing_ip, path=cleanbrowsing_path, verify=False)
        self.assertTrue(q.is_response(r))

    def test_use_full_url(self):
        pass

if __name__ == '__main__':
    unittest.main()
