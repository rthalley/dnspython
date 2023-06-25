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
import dns.exception
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY

try:
    from dns.dnssecalgs import (
        get_algorithm_cls,
        get_algorithm_cls_from_dnskey,
        register_algorithm_cls,
    )
    from dns.dnssecalgs.dsa import PrivateDSA, PrivateDSANSEC3SHA1
    from dns.dnssecalgs.ecdsa import PrivateECDSAP256SHA256, PrivateECDSAP384SHA384
    from dns.dnssecalgs.eddsa import PrivateED448, PrivateED25519, PublicED25519
    from dns.dnssecalgs.rsa import (
        PrivateRSAMD5,
        PrivateRSASHA1,
        PrivateRSASHA1NSEC3SHA1,
        PrivateRSASHA256,
        PrivateRSASHA512,
    )
except ImportError:
    pass  # Cryptography ImportError already handled in dns.dnssec


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
        _ = private_cls(key=private_key.key)
        _ = public_cls(key=public_key.key)

        # to/from PEM
        password = b"mekmitasdigoat"
        private_pem = private_key.to_pem()
        private_pem_encrypted = private_key.to_pem(password=password)
        public_pem = public_key.to_pem()
        _ = private_cls.from_pem(private_pem)
        _ = private_cls.from_pem(private_pem_encrypted, password)
        _ = public_cls.from_pem(public_pem)

    def test_rsa(self):
        self._test_dnssec_alg(PrivateRSAMD5, 2048)
        self._test_dnssec_alg(PrivateRSASHA1, 2048)
        self._test_dnssec_alg(PrivateRSASHA1NSEC3SHA1, 2048)
        self._test_dnssec_alg(PrivateRSASHA256, 2048)
        self._test_dnssec_alg(PrivateRSASHA512, 2048)

    def test_dsa(self):
        self._test_dnssec_alg(PrivateDSA, 1024)
        self._test_dnssec_alg(PrivateDSANSEC3SHA1, 1024)
        with self.assertRaises(ValueError):
            k = PrivateDSA.generate(2048)
            k.sign(b"hello")

    def test_ecdsa(self):
        self._test_dnssec_alg(PrivateECDSAP256SHA256)
        self._test_dnssec_alg(PrivateECDSAP384SHA384)

    def test_eddsa(self):
        self._test_dnssec_alg(PrivateED25519)
        self._test_dnssec_alg(PrivateED448)

    def test_algorithm_mismatch(self):
        private_key_ed448 = PrivateED448.generate()
        dnskey_ed448 = private_key_ed448.public_key().to_dnskey()
        with self.assertRaises(dns.exception.AlgorithmKeyMismatch):
            PublicED25519.from_dnskey(dnskey_ed448)


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class DNSSECAlgorithmPrivateAlgorithm(unittest.TestCase):
    def test_private(self):
        class PublicExampleAlgorithm(PublicED25519):
            algorithm = Algorithm.PRIVATEDNS
            name = dns.name.from_text("algorithm.example.com")

            def encode_key_bytes(self) -> bytes:
                return self.name.to_wire() + super().encode_key_bytes()

            @classmethod
            def from_dnskey(cls, key: DNSKEY) -> "PublicEDDSA":
                return cls(
                    key=cls.key_cls.from_public_bytes(
                        key.key[len(cls.name.to_wire()) :]
                    ),
                )

        class PrivateExampleAlgorithm(PrivateED25519):
            public_cls = PublicExampleAlgorithm

        register_algorithm_cls(
            algorithm=Algorithm.PRIVATEDNS,
            algorithm_cls=PrivateExampleAlgorithm,
            name=PublicExampleAlgorithm.name,
        )

        private_key = PrivateExampleAlgorithm.generate()
        public_key = private_key.public_key()

        name = dns.name.from_text("example.com")
        rdataset = dns.rdataset.from_text_list("in", "a", 30, ["10.0.0.1", "10.0.0.2"])
        rrset = (name, rdataset)
        ttl = 60
        lifetime = 3600
        rrname = rrset[0]
        signer = rrname
        dnskey = dns.dnssec.make_dnskey(
            public_key=public_key, algorithm=Algorithm.PRIVATEDNS
        )
        dnskey_rrset = dns.rrset.from_rdata(signer, ttl, dnskey)

        rrsig = dns.dnssec.sign(
            rrset=rrset,
            private_key=private_key,
            dnskey=dnskey,
            lifetime=lifetime,
            signer=signer,
            verify=True,
            policy=None,
        )

        keys = {signer: dnskey_rrset}
        rrsigset = dns.rrset.from_rdata(rrname, ttl, rrsig)
        dns.dnssec.validate(rrset=rrset, rrsigset=rrsigset, keys=keys, policy=None)

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
        register_algorithm_cls(
            algorithm=251,
            algorithm_cls=PrivateED25519,
        )

        with self.assertRaises(TypeError):
            register_algorithm_cls(algorithm=251, algorithm_cls=str, name="example.com")

        with self.assertRaises(ValueError):
            register_algorithm_cls(
                algorithm=251, algorithm_cls=PrivateED25519, name="example.com"
            )

        with self.assertRaises(ValueError):
            register_algorithm_cls(
                algorithm=251, algorithm_cls=PrivateED25519, oid=bytes([1, 2, 3, 4])
            )

        with self.assertRaises(ValueError):
            register_algorithm_cls(
                algorithm=Algorithm.PRIVATEDNS,
                algorithm_cls=PrivateED25519,
                oid=bytes([1, 2, 3, 4]),
            )

        with self.assertRaises(ValueError):
            register_algorithm_cls(
                algorithm=Algorithm.PRIVATEOID,
                algorithm_cls=PrivateED25519,
                name="example.com",
            )

        dnskey_251 = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            3,
            251,
            b"hello",
        )
        dnskey_dns = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            3,
            Algorithm.PRIVATEDNS,
            dns.name.from_text("ed25519.example.com").to_wire() + b"hello",
        )
        dnskey_dns_unknown = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            3,
            Algorithm.PRIVATEDNS,
            dns.name.from_text("unknown.example.com").to_wire() + b"hello",
        )
        dnskey_oid = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            3,
            Algorithm.PRIVATEOID,
            bytes([4, 1, 2, 3, 4]) + b"hello",
        )
        dnskey_oid_unknown = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            3,
            Algorithm.PRIVATEOID,
            bytes([4, 42, 42, 42, 42]) + b"hello",
        )

        with self.assertRaises(dns.exception.UnsupportedAlgorithm):
            _ = get_algorithm_cls(250)

        algorithm_cls = get_algorithm_cls(251)
        self.assertEqual(algorithm_cls, PrivateED25519)

        algorithm_cls = get_algorithm_cls_from_dnskey(dnskey_251)
        self.assertEqual(algorithm_cls, PrivateED25519)

        algorithm_cls = get_algorithm_cls_from_dnskey(dnskey_dns)
        self.assertEqual(algorithm_cls, PrivateED25519)

        with self.assertRaises(dns.exception.UnsupportedAlgorithm):
            _ = get_algorithm_cls_from_dnskey(dnskey_dns_unknown)

        algorithm_cls = get_algorithm_cls_from_dnskey(dnskey_oid)
        self.assertEqual(algorithm_cls, PrivateED448)

        with self.assertRaises(dns.exception.UnsupportedAlgorithm):
            _ = get_algorithm_cls_from_dnskey(dnskey_oid_unknown)

    def test_register_canonical_lookup(self):
        register_algorithm_cls(
            algorithm=Algorithm.PRIVATEDNS,
            algorithm_cls=PrivateED25519,
            name="testing1234.example.com",
        )

        dnskey_dns = DNSKEY(
            "IN",
            "DNSKEY",
            256,
            3,
            Algorithm.PRIVATEDNS,
            dns.name.from_text("TESTING1234.EXAMPLE.COM").to_wire() + b"hello",
        )

        algorithm_cls = get_algorithm_cls_from_dnskey(dnskey_dns)
        self.assertEqual(algorithm_cls, PrivateED25519)

    def test_register_private_without_prefix(self):
        with self.assertRaises(ValueError):
            register_algorithm_cls(
                algorithm=Algorithm.PRIVATEDNS,
                algorithm_cls=PrivateED25519,
            )
        with self.assertRaises(ValueError):
            register_algorithm_cls(
                algorithm=Algorithm.PRIVATEOID,
                algorithm_cls=PrivateED25519,
            )


if __name__ == "__main__":
    unittest.main()
