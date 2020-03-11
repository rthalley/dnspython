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
import base64
import unittest
import random

import requests
from requests.exceptions import SSLError

import dns.query
import dns.rdatatype
import dns.message

KNOWN_ANYCAST_DOH_RESOLVER_IPS = ['1.1.1.1', '8.8.8.8', '9.9.9.9']
KNOWN_ANYCAST_DOH_RESOLVER_URLS = ['https://cloudflare-dns.com/dns-query',
                                   'https://dns.google/dns-query',
                                   'https://dns11.quad9.net/dns-query']

class DNSOverHTTPSTestCase(unittest.TestCase):
    def setUp(self):
        self.session = requests.sessions.Session()

    def tearDown(self):
        self.session.close()

    def test_get_request(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        r = dns.query.https(q, nameserver_url, session=self.session, post=False)
        self.assertTrue(q.is_response(r))

    def test_post_request(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        r = dns.query.https(q, nameserver_url, session=self.session, post=True)
        self.assertTrue(q.is_response(r))

    def test_build_url_from_ip(self):
        nameserver_ip = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_IPS)
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        # For some reason Google's DNS over HTTPS fails when you POST to https://8.8.8.8/dns-query
        # So we're just going to do GET requests here
        r = dns.query.https(q, nameserver_ip, session=self.session, post=False)
        self.assertTrue(q.is_response(r))

    def test_bootstrap_address(self):
        ip = '185.228.168.168'
        invalid_tls_url = 'https://{}/doh/family-filter/'.format(ip)
        valid_tls_url = 'https://doh.cleanbrowsing.org/doh/family-filter/'
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        # make sure CleanBrowsing's IP address will fail TLS certificate check
        with self.assertRaises(SSLError):
            dns.query.https(q, invalid_tls_url, session=self.session)
        # use host header
        r = dns.query.https(q, valid_tls_url, session=self.session, bootstrap_address=ip)
        self.assertTrue(q.is_response(r))

    def test_send_https(self):
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        wire = q.to_wire()
        query_string = '?dns={}'.format(base64.urlsafe_b64encode(wire).decode('utf-8').strip("="))
        request = requests.models.Request(
            'GET',
            'https://cloudflare-dns.com/dns-query{}'.format(query_string))
        r = request.prepare()
        response = dns.query.send_https(self.session, r)
        dns_resp = dns.message.from_wire(response.content)
        self.assertTrue(q.is_response(dns_resp))

    def test_new_session(self):
        nameserver_url = random.choice(KNOWN_ANYCAST_DOH_RESOLVER_URLS)
        q = dns.message.make_query('example.com.', dns.rdatatype.A)
        r = dns.query.https(q, nameserver_url)
        self.assertTrue(q.is_response(r))

if __name__ == '__main__':
    unittest.main()
