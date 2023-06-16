# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2011 Nominum, Inc.
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

import os
import unittest

import dns.dnssec
from dns.dnssecalgs import get_algorithm_cls, register_algorithm_cls
from dns.dnssecalgs.dsa import PrivateDSA, PrivateDSANSEC3SHA1
from dns.dnssecalgs.ecdsa import PrivateECDSAP256SHA256, PrivateECDSAP384SHA384
from dns.dnssecalgs.eddsa import PrivateED448, PrivateED25519
from dns.dnssecalgs.rsa import (
    PrivateRSAMD5,
    PrivateRSASHA1,
    PrivateRSASHA1NSEC3SHA1,
    PrivateRSASHA256,
    PrivateRSASHA512,
)
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class DNSSECAlgorithm(unittest.TestCase):
    def _test_dnssec_alg(self, private_cls, key_size=None):
        public_cls = private_cls.public_cls

        private_key = (
            private_cls.generate(key_size) if key_size else private_cls.generate()
        )

        # sign random data
        data = os.urandom(1024)
        signature = private_key.sign(data, verify=True)

        # validate signature using public key
        public_key = private_key.public_key()
        public_key.verify(signature, data)

        # create DNSKEY
        dnskey = public_key.to_dnskey()
        dnskey2 = public_cls.from_dnskey(dnskey).to_dnskey()
        self.assertEqual(dnskey, dnskey2)

        # test cryptography keys
        _ = private_cls.from_key(private_key.key)
        _ = public_cls.from_key(public_key.key)

    def test_rsa(self):
        self._test_dnssec_alg(PrivateRSAMD5, 2048)
        self._test_dnssec_alg(PrivateRSASHA1, 2048)
        self._test_dnssec_alg(PrivateRSASHA1NSEC3SHA1, 2048)
        self._test_dnssec_alg(PrivateRSASHA256, 2048)
        self._test_dnssec_alg(PrivateRSASHA512, 2048)

    def test_dsa(self):
        self._test_dnssec_alg(PrivateDSA, 1024)
        self._test_dnssec_alg(PrivateDSANSEC3SHA1, 1024)

    def test_ecdsa(self):
        self._test_dnssec_alg(PrivateECDSAP256SHA256)
        self._test_dnssec_alg(PrivateECDSAP384SHA384)

    def test_eddsa(self):
        self._test_dnssec_alg(PrivateED25519)
        self._test_dnssec_alg(PrivateED448)

    def test_register(self):
        register_algorithm_cls(
            algorithm=Algorithm.PRIVATEDNS,
            algorithm_cls=PrivateED25519,
            name="ed25519.example.com",
        )
        register_algorithm_cls(
            algorithm=Algorithm.PRIVATEOID,
            algorithm_cls=PrivateED448,
            oid=bytes([1, 2, 3, 4]),
        )

        dnskey_dns = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            5,
            Algorithm.PRIVATEDNS,
            dns.name.from_text("ed25519.example.com").to_wire() + b"hello",
        )
        dnskey_oid = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            5,
            Algorithm.PRIVATEOID,
            bytes([4, 1, 2, 3, 4]) + b"hello",
        )

        algorithm_cls = get_algorithm_cls(dnskey_dns)
        self.assertEqual(algorithm_cls, PrivateED25519)

        algorithm_cls = get_algorithm_cls(dnskey_oid)
        self.assertEqual(algorithm_cls, PrivateED448)

        breakpoint()


if __name__ == "__main__":
    unittest.main()
