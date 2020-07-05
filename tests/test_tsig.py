# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest
from unittest.mock import Mock

import dns.rcode
import dns.tsig
import dns.tsigkeyring
import dns.message

keyring = dns.tsigkeyring.from_text(
    {
        'keyname.' : 'NjHwPsMKjdN++dOfE5iAiQ=='
    }
)

keyname = dns.name.from_text('keyname')


class TSIGTestCase(unittest.TestCase):

    def test_get_context(self):
        key = dns.tsig.Key('foo.com', 'abcd', 'hmac-sha256')
        ctx = dns.tsig.get_context(key)
        self.assertEqual(ctx.name, 'hmac-sha256')
        key = dns.tsig.Key('foo.com', 'abcd', 'hmac-sha512')
        ctx = dns.tsig.get_context(key)
        self.assertEqual(ctx.name, 'hmac-sha512')
        bogus = dns.tsig.Key('foo.com', 'abcd', 'bogus')
        with self.assertRaises(NotImplementedError):
            dns.tsig.get_context(bogus)

    def test_tsig_message_properties(self):
        m = dns.message.make_query('example', 'a')
        self.assertIsNone(m.keyname)
        self.assertIsNone(m.keyalgorithm)
        self.assertIsNone(m.tsig_error)
        m.use_tsig(keyring, keyname)
        self.assertEqual(m.keyname, keyname)
        self.assertEqual(m.keyalgorithm, dns.tsig.default_algorithm)
        self.assertEqual(m.tsig_error, dns.rcode.NOERROR)
        m = dns.message.make_query('example', 'a')
        m.use_tsig(keyring, keyname, tsig_error=dns.rcode.BADKEY)
        self.assertEqual(m.tsig_error, dns.rcode.BADKEY)

    def test_gssapi_context(self):
        # mock out the gssapi context to return some dummy values
        gssapi_context_mock = Mock()
        gssapi_context_mock.get_signature.return_value = b'xxxxxxxxxxx'
        gssapi_context_mock.verify_signature.return_value = None

        # create the key and add it to the keyring
        key = dns.tsig.Key('gsstsigtest', gssapi_context_mock, 'gss-tsig')
        ctx = dns.tsig.get_context(key)
        self.assertEqual(ctx.name, 'gss-tsig')
        gsskeyname = dns.name.from_text('gsstsigtest')
        keyring[gsskeyname] = key

        # create example message and go to/from wire to simulate sign/verify
        m = dns.message.make_query('example', 'a')
        m.use_tsig(keyring, gsskeyname)
        w = m.to_wire()
        # not raising is passing
        dns.message.from_wire(w, keyring)

        # assertions to make sure the "gssapi" functions were called
        gssapi_context_mock.get_signature.assert_called_once()
        gssapi_context_mock.verify_signature.assert_called_once()

    def test_sign_and_validate(self):
        m = dns.message.make_query('example', 'a')
        m.use_tsig(keyring, keyname)
        w = m.to_wire()
        # not raising is passing
        dns.message.from_wire(w, keyring)

    def test_sign_and_validate_with_other_data(self):
        m = dns.message.make_query('example', 'a')
        m.use_tsig(keyring, keyname, other_data=b'other')
        w = m.to_wire()
        # not raising is passing
        dns.message.from_wire(w, keyring)

    def make_message_pair(self, qname='example', rdtype='A', tsig_error=0):
        q = dns.message.make_query(qname, rdtype)
        q.use_tsig(keyring=keyring, keyname=keyname)
        q.to_wire()  # to set q.mac
        r = dns.message.make_response(q, tsig_error=tsig_error)
        return(q, r)

    def test_peer_errors(self):
        items = [(dns.rcode.BADSIG, dns.tsig.PeerBadSignature),
                 (dns.rcode.BADKEY, dns.tsig.PeerBadKey),
                 (dns.rcode.BADTIME, dns.tsig.PeerBadTime),
                 (dns.rcode.BADTRUNC, dns.tsig.PeerBadTruncation),
                 (99, dns.tsig.PeerError),
                 ]
        for err, ex in items:
            q, r = self.make_message_pair(tsig_error=err)
            w = r.to_wire()
            def bad():
                dns.message.from_wire(w, keyring=keyring, request_mac=q.mac)
            self.assertRaises(ex, bad)
