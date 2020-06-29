# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

import dns.exception
import dns.message
import dns.renderer
import dns.flags

basic_answer = \
    """flags QR
edns 0
payload 4096
;QUESTION
foo.example. IN A
;ANSWER
foo.example. 30 IN A 10.0.0.1
foo.example. 30 IN A 10.0.0.2
"""

class RendererTestCase(unittest.TestCase):
    def test_basic(self):
        r = dns.renderer.Renderer(flags=dns.flags.QR, max_size=512)
        qname = dns.name.from_text('foo.example')
        r.add_question(qname, dns.rdatatype.A)
        rds = dns.rdataset.from_text('in', 'a', 30, '10.0.0.1', '10.0.0.2')
        r.add_rdataset(dns.renderer.ANSWER, qname, rds)
        r.add_edns(0, 0, 4096)
        r.write_header()
        wire = r.get_wire()
        message = dns.message.from_wire(wire)
        expected = dns.message.from_text(basic_answer)
        # Our rendered message purposely has a random query id so we
        # exercise that code, so copy it into the expected message.
        expected.id = message.id
        self.assertEqual(message, expected)

    def test_going_backwards_fails(self):
        r = dns.renderer.Renderer(flags=dns.flags.QR, max_size=512)
        qname = dns.name.from_text('foo.example')
        r.add_question(qname, dns.rdatatype.A)
        r.add_edns(0, 0, 4096)
        rds = dns.rdataset.from_text('in', 'a', 30, '10.0.0.1', '10.0.0.2')
        def bad():
            r.add_rdataset(dns.renderer.ANSWER, qname, rds)
        self.assertRaises(dns.exception.FormError, bad)
