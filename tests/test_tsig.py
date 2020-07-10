# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest
from unittest.mock import Mock
import time

import dns.rcode
import dns.tsig
import dns.tsigkeyring
import dns.message
from dns.rdatatype import RdataType
from dns.rdataclass import RdataClass

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

    def test_verify_mac_for_context(self):
        dummy_ctx = None
        dummy_expected = None
        key = dns.tsig.Key('foo.com', 'abcd', 'bogus')
        with self.assertRaises(NotImplementedError):
            dns.tsig._verify_mac_for_context(dummy_ctx, key, dummy_expected)

        key = dns.tsig.Key('foo.com', 'abcd', 'hmac-sha512')
        ctx = dns.tsig.get_context(key)
        bad_expected = b'xxxxxxxxxx'
        with self.assertRaises(dns.tsig.BadSignature):
            dns.tsig._verify_mac_for_context(ctx, key, bad_expected)

    def test_validate(self):
        # make message and grab the TSIG
        m = dns.message.make_query('example', 'a')
        m.use_tsig(keyring, keyname, algorithm=dns.tsig.HMAC_SHA256)
        w = m.to_wire()
        tsig = m.tsig[0]

        # get the time and create a key with matching characteristics
        now = int(time.time())
        key = dns.tsig.Key('foo.com', 'abcd', 'hmac-sha256')

        # add enough to the time to take it over the fudge amount
        with self.assertRaises(dns.tsig.BadTime):
            dns.tsig.validate(w, key, dns.name.from_text('foo.com'),
                              tsig, now + 1000, b'', 0)

        # change the key name
        with self.assertRaises(dns.tsig.BadKey):
            dns.tsig.validate(w, key, dns.name.from_text('bar.com'),
                              tsig, now, b'', 0)

        # change the key algorithm
        key = dns.tsig.Key('foo.com', 'abcd', 'hmac-sha512')
        with self.assertRaises(dns.tsig.BadAlgorithm):
            dns.tsig.validate(w, key, dns.name.from_text('foo.com'),
                              tsig, now, b'', 0)

    def test_gssapi_context(self):
        def verify_signature(data, mac):
            if data == b'throw':
                raise Exception
            return None

        # mock out the gssapi context to return some dummy values
        gssapi_context_mock = Mock()
        gssapi_context_mock.get_signature.return_value = b'xxxxxxxxxxx'
        gssapi_context_mock.verify_signature.side_effect = verify_signature

        # create the key and add it to the keyring
        key = dns.tsig.Key('gsstsigtest', gssapi_context_mock, 'gss-tsig')
        ctx = dns.tsig.get_context(key)
        self.assertEqual(ctx.name, 'gss-tsig')
        gsskeyname = dns.name.from_text('gsstsigtest')
        keyring[gsskeyname] = key

        # make sure we can get the keyring (no exception == success)
        text = dns.tsigkeyring.to_text(keyring)
        self.assertNotEqual(text, '')

        # test exceptional case for _verify_mac_for_context
        with self.assertRaises(dns.tsig.BadSignature):
            ctx.update(b'throw')
            dns.tsig._verify_mac_for_context(ctx, key, 'bogus')
        gssapi_context_mock.verify_signature.assert_called()
        self.assertEqual(gssapi_context_mock.verify_signature.call_count, 1)

        # create example message and go to/from wire to simulate sign/verify
        m = dns.message.make_query('example', 'a')
        m.use_tsig(keyring, gsskeyname)
        w = m.to_wire()
        # not raising is passing
        dns.message.from_wire(w, keyring)

        # assertions to make sure the "gssapi" functions were called
        gssapi_context_mock.get_signature.assert_called()
        self.assertEqual(gssapi_context_mock.get_signature.call_count, 1)
        gssapi_context_mock.verify_signature.assert_called()
        self.assertEqual(gssapi_context_mock.verify_signature.call_count, 2)

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
