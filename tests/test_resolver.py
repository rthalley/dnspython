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

import io
import select
import sys
import time
import unittest

import dns.name
import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver

resolv_conf = """
    /t/t
# comment 1
; comment 2
domain foo
nameserver 10.0.0.1
nameserver 10.0.0.2
"""

message_text = """id 1234
opcode QUERY
rcode NOERROR
flags QR AA RD
;QUESTION
example. IN A
;ANSWER
example. 1 IN A 10.0.0.1
;AUTHORITY
;ADDITIONAL
"""

dangling_cname_0_message_text = """id 10000
opcode QUERY
rcode NOERROR
flags QR AA RD RA
;QUESTION
91.11.17.172.in-addr.arpa.none. IN PTR
;ANSWER
;AUTHORITY
;ADDITIONAL
"""

dangling_cname_1_message_text = """id 10001
opcode QUERY
rcode NOERROR
flags QR AA RD RA
;QUESTION
91.11.17.172.in-addr.arpa. IN PTR
;ANSWER
11.17.172.in-addr.arpa. 86400 IN DNAME 11.8-22.17.172.in-addr.arpa.
91.11.17.172.in-addr.arpa. 86400 IN CNAME 91.11.8-22.17.172.in-addr.arpa.
;AUTHORITY
;ADDITIONAL
"""

dangling_cname_2_message_text = """id 10002
opcode QUERY
rcode NOERROR
flags QR AA RD RA
;QUESTION
91.11.17.172.in-addr.arpa.example. IN PTR
;ANSWER
91.11.17.172.in-addr.arpa.example. 86400 IN CNAME 91.11.17.172.in-addr.arpa.base.
91.11.17.172.in-addr.arpa.base. 86400 IN CNAME 91.11.17.172.clients.example.
91.11.17.172.clients.example. 86400 IN CNAME 91-11-17-172.dynamic.example.
;AUTHORITY
;ADDITIONAL
"""


class BaseResolverTests(object):

    if sys.platform != 'win32':
        def testRead(self):
            f = io.StringIO(resolv_conf)
            r = dns.resolver.Resolver(f)
            self.assertTrue(r.nameservers == ['10.0.0.1', '10.0.0.2'] and
                            r.domain == dns.name.from_text('foo'))

    def testCacheExpiration(self):
        message = dns.message.from_text(message_text)
        name = dns.name.from_text('example.')
        answer = dns.resolver.Answer(name, dns.rdatatype.A, dns.rdataclass.IN,
                                     message)
        cache = dns.resolver.Cache()
        cache.put((name, dns.rdatatype.A, dns.rdataclass.IN), answer)
        time.sleep(2)
        self.assertTrue(cache.get((name, dns.rdatatype.A, dns.rdataclass.IN))
                        is None)

    def testCacheCleaning(self):
        message = dns.message.from_text(message_text)
        name = dns.name.from_text('example.')
        answer = dns.resolver.Answer(name, dns.rdatatype.A, dns.rdataclass.IN,
                                     message)
        cache = dns.resolver.Cache(cleaning_interval=1.0)
        cache.put((name, dns.rdatatype.A, dns.rdataclass.IN), answer)
        time.sleep(2)
        self.assertTrue(cache.get((name, dns.rdatatype.A, dns.rdataclass.IN))
                        is None)

    def testZoneForName1(self):
        name = dns.name.from_text('www.dnspython.org.')
        ezname = dns.name.from_text('dnspython.org.')
        zname = dns.resolver.zone_for_name(name)
        self.assertTrue(zname == ezname)

    def testZoneForName2(self):
        name = dns.name.from_text('a.b.www.dnspython.org.')
        ezname = dns.name.from_text('dnspython.org.')
        zname = dns.resolver.zone_for_name(name)
        self.assertTrue(zname == ezname)

    def testZoneForName3(self):
        name = dns.name.from_text('dnspython.org.')
        ezname = dns.name.from_text('dnspython.org.')
        zname = dns.resolver.zone_for_name(name)
        self.assertTrue(zname == ezname)

    def testZoneForName4(self):
        def bad():
            name = dns.name.from_text('dnspython.org', None)
            zname = dns.resolver.zone_for_name(name)
        self.assertRaises(dns.resolver.NotAbsolute, bad)

class PollingMonkeyPatchMixin(object):
    def setUp(self):
        self.__native_polling_backend = dns.query._polling_backend
        dns.query._set_polling_backend(self.polling_backend())

        unittest.TestCase.setUp(self)

    def tearDown(self):
        dns.query._set_polling_backend(self.__native_polling_backend)

        unittest.TestCase.tearDown(self)

class SelectResolverTestCase(PollingMonkeyPatchMixin, BaseResolverTests, unittest.TestCase):
    def polling_backend(self):
        return dns.query._select_for

if hasattr(select, 'poll'):
    class PollResolverTestCase(PollingMonkeyPatchMixin, BaseResolverTests, unittest.TestCase):
        def polling_backend(self):
            return dns.query._poll_for

class NXDOMAINExceptionTestCase(unittest.TestCase):

    def test_nxdomain_compatible(self):
        n1 = dns.name.Name(('a', 'b', ''))
        n2 = dns.name.Name(('a', 'b', 's', ''))

        try:
            raise dns.resolver.NXDOMAIN
        except Exception as e:
            self.assertTrue((e.args == (e.__doc__,)))
            self.assertTrue(('kwargs' in dir(e)))
            self.assertTrue((str(e) == e.__doc__), str(e))
            self.assertTrue(('qnames' not in e.kwargs))
            self.assertTrue(('responses' not in e.kwargs))

        try:
            raise dns.resolver.NXDOMAIN("errmsg")
        except Exception as e:
            self.assertTrue((e.args == ("errmsg",)))
            self.assertTrue(('kwargs' in dir(e)))
            self.assertTrue((str(e) == "errmsg"), str(e))
            self.assertTrue(('qnames' not in e.kwargs))
            self.assertTrue(('responses' not in e.kwargs))

        try:
            raise dns.resolver.NXDOMAIN("errmsg", -1)
        except Exception as e:
            self.assertTrue((e.args == ("errmsg", -1)))
            self.assertTrue(('kwargs' in dir(e)))
            self.assertTrue((str(e) == "('errmsg', -1)"), str(e))
            self.assertTrue(('qnames' not in e.kwargs))
            self.assertTrue(('responses' not in e.kwargs))

        try:
            raise dns.resolver.NXDOMAIN(qnames=None)
        except Exception as e:
            self.assertTrue((isinstance(e, AttributeError)))

        try:
            raise dns.resolver.NXDOMAIN(qnames=n1)
        except Exception as e:
            self.assertTrue((isinstance(e, AttributeError)))

        try:
            raise dns.resolver.NXDOMAIN(qnames=[])
        except Exception as e:
            self.assertTrue((isinstance(e, AttributeError)))

        try:
            raise dns.resolver.NXDOMAIN(qnames=[n1])
        except Exception as e:
            self.assertTrue((e.args == (e.__doc__,)))
            self.assertTrue(('kwargs' in dir(e)))
            self.assertTrue((str(e) == "The DNS query name does not exist: a.b."), str(e))
            self.assertTrue(('qnames' in e.kwargs))
            self.assertTrue((e.kwargs['qnames'] == [n1]))
            self.assertTrue(('responses' in e.kwargs))
            self.assertTrue((e.kwargs['responses'] == {}))

        try:
            raise dns.resolver.NXDOMAIN(qnames=[n2, n1])
        except Exception as e:
            e0 = dns.resolver.NXDOMAIN("errmsg")
            e = e0 + e
            self.assertTrue((e.args == (e.__doc__,)), repr(e.args))
            self.assertTrue(('kwargs' in dir(e)))
            self.assertTrue((str(e) == "None of DNS query names exist: a.b.s., a.b."), str(e))
            self.assertTrue(('qnames' in e.kwargs))
            self.assertTrue((e.kwargs['qnames'] == [n2, n1]))
            self.assertTrue(('responses' in e.kwargs))
            self.assertTrue((e.kwargs['responses'] == {}))

        try:
            raise dns.resolver.NXDOMAIN(qnames=[n1], responses=['r1.1'])
        except Exception as e:
            self.assertTrue((isinstance(e, AttributeError)))

        try:
            raise dns.resolver.NXDOMAIN(qnames=[n1], responses={n1: 'r1.1'})
        except Exception as e:
            self.assertTrue((e.args == (e.__doc__,)))
            self.assertTrue(('kwargs' in dir(e)))
            self.assertTrue(('qnames' in e.kwargs))
            self.assertTrue((str(e) == "The DNS query name does not exist: a.b."), str(e))
            self.assertTrue((e.kwargs['qnames'] == [n1]))
            self.assertTrue(('responses' in e.kwargs))
            self.assertTrue((e.kwargs['responses'] == {n1: 'r1.1'}))

    def test_nxdomain_merge(self):
        n1 = dns.name.Name(('a', 'b', ''))
        n2 = dns.name.Name(('a', 'b', ''))
        n3 = dns.name.Name(('a', 'b', 'c', ''))
        n4 = dns.name.Name(('a', 'b', 'd', ''))
        responses1 = {n1: 'r1.1', n2: 'r1.2', n4: 'r1.4'}
        qnames1 = [n1, n4]   # n2 == n1
        responses2 = {n2: 'r2.2', n3: 'r2.3'}
        qnames2 = [n2, n3]
        e0 = dns.resolver.NXDOMAIN()
        e1 = dns.resolver.NXDOMAIN(qnames=qnames1, responses=responses1)
        e2 = dns.resolver.NXDOMAIN(qnames=qnames2, responses=responses2)
        e = e1 + e0 + e2
        self.assertTrue(e.kwargs['qnames'] == [n1, n4, n3], repr(e.kwargs['qnames']))
        self.assertTrue(e.kwargs['responses'][n1].startswith('r2.'))
        self.assertTrue(e.kwargs['responses'][n2].startswith('r2.'))
        self.assertTrue(e.kwargs['responses'][n3].startswith('r2.'))
        self.assertTrue(e.kwargs['responses'][n4].startswith('r1.'))

    def test_nxdomain_canonical_name(self):
        cname0 = "91.11.8-22.17.172.in-addr.arpa.none."
        cname1 = "91.11.8-22.17.172.in-addr.arpa."
        cname2 = "91-11-17-172.dynamic.example."
        message0 = dns.message.from_text(dangling_cname_0_message_text)
        message1 = dns.message.from_text(dangling_cname_1_message_text)
        message2 = dns.message.from_text(dangling_cname_2_message_text)
        qname0 = message0.question[0].name
        qname1 = message1.question[0].name
        qname2 = message2.question[0].name
        responses = {qname0: message0, qname1: message1, qname2: message2}
        e0 = dns.resolver.NXDOMAIN(qnames=[qname0], responses=responses)
        e1 = dns.resolver.NXDOMAIN(qnames=[qname0, qname1, qname2], responses=responses)
        e2 = dns.resolver.NXDOMAIN(qnames=[qname0, qname2, qname1], responses=responses)
        self.assertTrue(e0.canonical_name == qname0)
        self.assertTrue(e1.canonical_name == dns.name.from_text(cname1))
        self.assertTrue(e2.canonical_name == dns.name.from_text(cname2))

if __name__ == '__main__':
    unittest.main()
