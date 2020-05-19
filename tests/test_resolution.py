import unittest

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver

# Test the resolver's Resolution, i.e. the business logic of the resolver.

class ResolutionTestCase(unittest.TestCase):
    def setUp(self):
        self.resolver = dns.resolver.Resolver(configure=False)
        self.resolver.nameservers = ['10.0.0.1', '10.0.0.2']
        self.resolver.domain = dns.name.from_text('example')
        self.qname = dns.name.from_text('www.dnspython.org')
        self.resn = dns.resolver._Resolution(self.resolver, self.qname,
                                             'A', 'IN',
                                             False, True, False)

    def test_next_request_abs(self):
        (request, answer) = self.resn.next_request()
        self.assertTrue(answer is None)
        self.assertEqual(request.question[0].name, self.qname)
        self.assertEqual(request.question[0].rdtype, dns.rdatatype.A)

    def test_next_request_rel(self):
        qname = dns.name.from_text('www.dnspython.org', None)
        abs_qname_1 = dns.name.from_text('www.dnspython.org.example')
        self.resn = dns.resolver._Resolution(self.resolver, qname,
                                             'A', 'IN',
                                             False, True, False)
        (request, answer) = self.resn.next_request()
        self.assertTrue(answer is None)
        self.assertEqual(request.question[0].name, abs_qname_1)
        self.assertEqual(request.question[0].rdtype, dns.rdatatype.A)
        (request, answer) = self.resn.next_request()
        self.assertTrue(answer is None)
        self.assertEqual(request.question[0].name, self.qname)
        self.assertEqual(request.question[0].rdtype, dns.rdatatype.A)

    def test_next_request_exhaust_causes_nxdomain(self):
        def bad():
            (request, answer) = self.resn.next_request()
        (request, answer) = self.resn.next_request()
        self.assertRaises(dns.resolver.NXDOMAIN, bad)

    def test_next_request_cache_hit(self):
        self.resolver.cache = dns.resolver.Cache()
        q = dns.message.make_query(self.qname, dns.rdatatype.A)
        r = dns.message.make_response(q)
        rrs = r.get_rrset(r.answer, self.qname, dns.rdataclass.IN,
                          dns.rdatatype.A, create=True)
        rrs.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A,
                                    '10.0.0.1'), 300)
        cache_answer = dns.resolver.Answer(self.qname, dns.rdatatype.A,
                                           dns.rdataclass.IN, r)
        self.resolver.cache.put((self.qname, dns.rdatatype.A,
                                 dns.rdataclass.IN), cache_answer)
        (request, answer) = self.resn.next_request()
        self.assertTrue(request is None)
        self.assertTrue(answer is cache_answer)

    def test_next_request_no_answer(self):
        # In default mode, we should raise on a no-answer hit
        self.resolver.cache = dns.resolver.Cache()
        q = dns.message.make_query(self.qname, dns.rdatatype.A)
        r = dns.message.make_response(q)
        # We need an SOA so the cache doesn't expire the answer immediately.
        rrs = r.get_rrset(r.authority, self.qname, dns.rdataclass.IN,
                          dns.rdatatype.SOA, create=True)
        rrs.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.SOA,
                                    '. . 1 2 3 4 300'), 300)
        cache_answer = dns.resolver.Answer(self.qname, dns.rdatatype.A,
                                           dns.rdataclass.IN, r, False)
        self.resolver.cache.put((self.qname, dns.rdatatype.A,
                                 dns.rdataclass.IN), cache_answer)
        def bad():
            (request, answer) = self.resn.next_request()
        self.assertRaises(dns.resolver.NoAnswer, bad)
        # If raise_on_no_answer is False, we should get a cache hit.
        self.resn = dns.resolver._Resolution(self.resolver, self.qname,
                                             'A', 'IN',
                                             False, False, False)
        (request, answer) = self.resn.next_request()
        self.assertTrue(request is None)
        self.assertTrue(answer is cache_answer)

    def test_next_nameserver_udp(self):
        nameservers = {'10.0.0.1', '10.0.0.2'}
        (request, answer) = self.resn.next_request()
        (nameserver1, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver1 in nameservers)
        self.assertEqual(port, 53)
        self.assertFalse(tcp)
        self.assertEqual(backoff, 0.0)
        (nameserver2, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver2 in nameservers)
        self.assertTrue(nameserver2 != nameserver1)
        self.assertEqual(port, 53)
        self.assertFalse(tcp)
        self.assertEqual(backoff, 0.0)
        (nameserver3, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver3 is nameserver1)
        self.assertEqual(port, 53)
        self.assertFalse(tcp)
        self.assertEqual(backoff, 0.1)
        (nameserver4, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver4 is nameserver2)
        self.assertEqual(port, 53)
        self.assertFalse(tcp)
        self.assertEqual(backoff, 0.0)
        (nameserver5, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver5 is nameserver1)
        self.assertEqual(port, 53)
        self.assertFalse(tcp)
        self.assertEqual(backoff, 0.2)

    def test_next_nameserver_retry_with_tcp(self):
        nameservers = {'10.0.0.1', '10.0.0.2'}
        (request, answer) = self.resn.next_request()
        (nameserver1, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver1 in nameservers)
        self.assertEqual(port, 53)
        self.assertFalse(tcp)
        self.assertEqual(backoff, 0.0)
        self.resn.retry_with_tcp = True
        (nameserver2, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver2 is nameserver1)
        self.assertEqual(port, 53)
        self.assertTrue(tcp)
        self.assertEqual(backoff, 0.0)
        (nameserver3, port, tcp, backoff) = self.resn.next_nameserver()
        self.assertTrue(nameserver3 in nameservers)
        self.assertTrue(nameserver3 != nameserver1)
        self.assertEqual(port, 53)
        self.assertFalse(tcp)
        self.assertEqual(backoff, 0.0)

    def test_next_nameserver_no_nameservers(self):
        (request, answer) = self.resn.next_request()
        (nameserver, _, _, _) = self.resn.next_nameserver()
        self.resn.nameservers.remove(nameserver)
        (nameserver, _, _, _) = self.resn.next_nameserver()
        self.resn.nameservers.remove(nameserver)
        def bad():
            (nameserver, _, _, _) = self.resn.next_nameserver()
        self.assertRaises(dns.resolver.NoNameservers, bad)
