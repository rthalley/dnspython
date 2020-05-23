# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import socket
import unittest

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver

# Some tests require the internet to be available to run, so let's
# skip those if it's not there.
_network_available = True
try:
    socket.gethostbyname('dnspython.org')
except socket.gaierror:
    _network_available = False

@unittest.skipIf(not _network_available, "Internet not reachable")
class OverrideSystemResolverTestCase(unittest.TestCase):
    def test_override(self):
        res = dns.resolver.Resolver()
        res.nameservers = ['8.8.8.8']
        res.cache = dns.resolver.LRUCache()
        dns.resolver.override_system_resolver(res)
        self.assertTrue(socket.getaddrinfo is
                        dns.resolver._getaddrinfo)
        socket.gethostbyname('www.dnspython.org')
        answer = res.cache.get((dns.name.from_text('www.dnspython.org.'),
                                dns.rdatatype.A, dns.rdataclass.IN))
        self.assertTrue(answer is not None)
        res.cache.flush()
        socket.gethostbyname_ex('www.dnspython.org')
        answer = res.cache.get((dns.name.from_text('www.dnspython.org.'),
                                dns.rdatatype.A, dns.rdataclass.IN))
        self.assertTrue(answer is not None)
        res.cache.flush()
        socket.getfqdn('8.8.8.8')
        answer = res.cache.get((dns.name.from_text('8.8.8.8.in-addr.arpa.'),
                                dns.rdatatype.PTR, dns.rdataclass.IN))
        self.assertTrue(answer is not None)
        res.cache.flush()
        socket.gethostbyaddr('8.8.8.8')
        answer = res.cache.get((dns.name.from_text('8.8.8.8.in-addr.arpa.'),
                                dns.rdatatype.PTR, dns.rdataclass.IN))
        self.assertTrue(answer is not None)
        dns.resolver.restore_system_resolver()
        self.assertTrue(socket.getaddrinfo is
                        dns.resolver._original_getaddrinfo)
