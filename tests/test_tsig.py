# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import hashlib
import unittest
from unittest.mock import Mock

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

    def test_get_algorithm(self):
        n = dns.name.from_text('hmac-sha256')
        (w, alg) = dns.tsig.get_algorithm(n)
        self.assertEqual(alg, hashlib.sha256)
        (w, alg) = dns.tsig.get_algorithm('hmac-sha256')
        self.assertEqual(alg, hashlib.sha256)
        self.assertRaises(NotImplementedError,
                          lambda: dns.tsig.get_algorithm('bogus'))

    def test_hmac_context(self):
        tsig_type = dns.tsig.get_tsig_class('hmac-sha512')
        self.assertEqual(
            tsig_type.algorithm_name(), dns.name.from_text('hmac-sha512')
        )

        hmac = tsig_type(b'12345')
        hmac.update(b'abcdef')
        ctx = hmac.ctx
        self.assertEqual(ctx.impl, hashlib.sha512)
        self.assertEqual(type(ctx.data).__name__, 'HMAC')
        signature = hmac.sign()
        expected = \
            (
                b'\xd3\xc0\x7f/zx\x88\xb5p\x16\xbb\x9a7['
                b'ZbWY\x06l\x03z\xf8\t\xb1\xf06X;\x8aFi'
                b'y\x06\x84"\xa1\xe6R\xf9\x14:\n\x7f`\xcc9\xbf\xe5L\x9b\xbe['
                b'4\xbc\xe7'
                b'\x1f\x17\x05\x84u\x94\t\xcb'
            )
        self.assertEqual(signature, expected)
        self.assertEqual(hmac.verify(expected), None)

    def test_gssapi_context(self):
        tsig_type = dns.tsig.get_tsig_class('gss-tsig')
        self.assertEqual(
            tsig_type.algorithm_name(), dns.name.from_text('gss-tsig')
        )

        gssapi = Mock()
        gssapi.get_signature.return_value = 'abcdef'
        gssapi.verify_signature.return_value = None

        # create the tsig
        gssapi_tsig = tsig_type(gssapi)
        # update it
        gssapi_tsig.update(b'12345')
        # sign/verify
        sig = gssapi_tsig.sign()
        gssapi_tsig.verify(sig)

        # assertions
        gssapi.get_signature.assert_called_once_with(b'12345')
        gssapi.verify_signature.assert_called_once_with(b'12345', sig)

    def test_sign_and_validate(self):
        m = dns.message.make_query('example', 'a')
        m.use_tsig(keyring, keyname)
        w = m.to_wire()
        # not raising is passing
        dns.message.from_wire(w, keyring)

    def test_sign_and_validate_with_other_data(self):
        m = dns.message.make_query('example', 'a')
        other = b'other data'
        m.use_tsig(keyring, keyname, other_data=b'other')
        w = m.to_wire()
        # not raising is passing
        dns.message.from_wire(w, keyring)

    def make_message_pair(self, qname='example', rdtype='A'):
        q = dns.message.make_query(qname, rdtype)
        q.use_tsig(keyring=keyring, keyname=keyname)
        q.had_tsig = True  # so make_response() does the right thing
        q.to_wire()  # to set q.mac
        r = dns.message.make_response(q)
        return(q, r)

    def test_peer_errors(self):
        items = [(dns.tsig.BADSIG, dns.tsig.PeerBadSignature),
                 (dns.tsig.BADKEY, dns.tsig.PeerBadKey),
                 (dns.tsig.BADTIME, dns.tsig.PeerBadTime),
                 (dns.tsig.BADTRUNC, dns.tsig.PeerBadTruncation),
                 (99, dns.tsig.PeerError),
                 ]
        for err, ex in items:
            q, r = self.make_message_pair()
            r.tsig_error = err
            w = r.to_wire()
            def bad():
                dns.message.from_wire(w, keyring=keyring, request_mac=q.mac)
            self.assertRaises(ex, bad)
