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

from base64 import decode
import os
import re
import sys
import unittest
import unittest.mock

import dns._features
import dns.dnssec
import dns.exception
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from pathlib import Path
import tempfile

try:
    from dns.dnssecalgs import (
        get_algorithm_cls,
        get_algorithm_cls_from_dnskey,
        register_algorithm_cls,
    )
    from dns.dnssecalgs.dsa import PrivateDSA, PrivateDSANSEC3SHA1, PublicDSA
    from dns.dnssecalgs.ecdsa import (
        PrivateECDSAP256SHA256,
        PrivateECDSAP384SHA384,
        PublicECDSAP384SHA384,
        PublicECDSAP256SHA256,
    )
    from dns.dnssecalgs.eddsa import PrivateED448, PrivateED25519, PublicED25519
    from dns.dnssecalgs.mldsa import PrivateMLDSA44, PublicMLDSA44
    from dns.dnssecalgs.rsa import (
        PrivateRSA,
        PrivateRSAMD5,
        PrivateRSASHA1,
        PrivateRSASHA1NSEC3SHA1,
        PrivateRSASHA256,
        PrivateRSASHA512,
    )
    from dns.dnssecalgs.serialization import Key, _encode_name, _decode_name
except ImportError:
    pass  # Cryptography ImportError already handled in dns.dnssec

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
except ImportError:
    pass  # Cryptography ImportError already handled in dns.dnssec

    def default_backend():
        raise NotImplementedError


if dns.dnssec._have_pyca:
    have_deterministic = default_backend().ecdsa_deterministic_supported()
    have_mldsa = default_backend().mldsa_supported()
else:
    have_deterministic = False
    have_mldsa = False

KEYS_DIRECTORY = Path(os.path.dirname(__file__)) / "dnsseckeys"


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

    @unittest.skipUnless(have_deterministic, "deterministic ECDSA not available")
    def test_ecdsa(self):
        self._test_dnssec_alg(PrivateECDSAP256SHA256)
        self._test_dnssec_alg(PrivateECDSAP384SHA384)

    def test_eddsa(self):
        self._test_dnssec_alg(PrivateED25519)
        self._test_dnssec_alg(PrivateED448)

    @unittest.skipUnless(have_mldsa, "ML-DSA is not available")
    def test_mldsa(self):
        self._test_dnssec_alg(PrivateMLDSA44)

    def test_algorithm_mismatch(self):
        private_key_ed448 = PrivateED448.generate()
        dnskey_ed448 = private_key_ed448.public_key().to_dnskey()
        with self.assertRaises(dns.exception.AlgorithmKeyMismatch):
            PublicED25519.from_dnskey(dnskey_ed448)

    def _truncated_dnskey(self, algorithm, key_material):
        wire = b"\x01\x00\x03" + bytes([algorithm]) + key_material
        return dns.rdata.from_wire(
            dns.rdataclass.IN, dns.rdatatype.DNSKEY, wire, 0, len(wire)
        )

    def test_truncated_dsa(self):
        good = PrivateDSA.generate(1024).public_key().to_dnskey().key
        for key_material in (b"", good[:1], good[:21], good[:-1]):
            dnskey = self._truncated_dnskey(Algorithm.DSA, key_material)
            with self.assertRaises(ValueError):
                PublicDSA.from_dnskey(dnskey)

    @unittest.skipUnless(have_deterministic, "deterministic ECDSA not available")
    def test_truncated_ecdsa(self):
        for private_cls in (PrivateECDSAP256SHA256, PrivateECDSAP384SHA384):
            public_cls = private_cls.public_cls
            good = private_cls.generate().public_key().to_dnskey().key
            for key_material in (b"", good[: public_cls.octets], good[:-1]):
                dnskey = self._truncated_dnskey(public_cls.algorithm, key_material)
                with self.assertRaises(ValueError):
                    public_cls.from_dnskey(dnskey)

    def _check_bad_signatures(self, private_key, signature, bad_signatures):
        data = b"hello"
        public_key = private_key.public_key()
        public_key.verify(signature, data)
        for bad in bad_signatures:
            with self.assertRaises(InvalidSignature):
                public_key.verify(bad, data)

    def test_dsa_signature_length(self):
        private_key = PrivateDSA.generate(1024)
        sig = private_key.sign(b"hello")
        self._check_bad_signatures(
            private_key,
            sig,
            (
                sig[:21] + b"\x00" + sig[21:],
                sig + b"\x00",
                sig[:-1],
                bytes([sig[0] ^ 1]) + sig[1:],
            ),
        )

    def test_ecdsa_curve_mismatch(self):
        private_key_p256 = PrivateECDSAP256SHA256.generate()
        with self.assertRaises(dns.exception.AlgorithmKeyMismatch):
            PrivateECDSAP384SHA384(private_key_p256.key)
        with self.assertRaises(dns.exception.AlgorithmKeyMismatch):
            PublicECDSAP384SHA384(private_key_p256.key.public_key())

        private_key_p384 = PrivateECDSAP384SHA384.generate()
        with self.assertRaises(dns.exception.AlgorithmKeyMismatch):
            PrivateECDSAP256SHA256(private_key_p384.key)
        with self.assertRaises(dns.exception.AlgorithmKeyMismatch):
            PublicECDSAP256SHA256(private_key_p384.key.public_key())

    @unittest.skipUnless(have_deterministic, "deterministic ECDSA not available")
    def test_ecdsa_signature_length(self):
        for private_cls in (PrivateECDSAP256SHA256, PrivateECDSAP384SHA384):
            octets = private_cls.public_cls.octets
            private_key = private_cls.generate()
            sig = private_key.sign(b"hello")
            self._check_bad_signatures(
                private_key,
                sig,
                (
                    sig[:octets] + b"\x00" + sig[octets:],
                    sig[:octets] + b"\x00\x00\x00" + sig[octets:],
                    sig + b"\x00",
                    sig[:-1],
                ),
            )


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


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class DNSSECKey(unittest.TestCase):

    def test_import_export_bind_private_key(self):
        """Test importing and exporting BIND private keys."""

        for private_key_file in KEYS_DIRECTORY.glob("K*.private"):

            if match := re.match(r"K.*\+.*\+(\d{5})\.private", private_key_file.name):
                expected_key_id = int(match.group(1))
            else:
                raise ValueError(
                    f"Invalid private key filename: {private_key_file.name}"
                )

            key_from_bind = Key.from_bind(private_key_file)

            assert key_from_bind.key_id() == expected_key_id
            assert key_from_bind.key_id() == dns.dnssec.key_id(key_from_bind.dnskey)

            assert (
                key_from_bind.private.public_key().to_dnskey() == key_from_bind.dnskey
            )

            with tempfile.TemporaryDirectory() as temp_dir:
                new_private_filename = key_from_bind.to_bind(Path(temp_dir))
                assert new_private_filename.exists()

                new_private_filename.unlink()
                new_private_filename.with_suffix(".key").unlink()

                new_public_filename = key_from_bind.to_bind(
                    Path(temp_dir), public_only=True
                )
                assert new_public_filename.exists()
                assert new_private_filename.exists() is False
                new_public_filename.unlink()

                new_private_filename = key_from_bind.to_bind(Path(temp_dir))
                assert new_private_filename.exists()

                with self.assertRaises(FileExistsError):
                    new_private_filename = key_from_bind.to_bind(
                        Path(temp_dir), overwrite=False
                    )
                    assert new_private_filename.exists()

                new_private_filename = key_from_bind.to_bind(
                    Path(temp_dir), overwrite=True
                )
                assert new_private_filename.exists()
                # windows ignores our mode bits
                if sys.platform != "win32":
                    stat = os.stat(new_private_filename)
                    assert stat.st_mode & 0o777 == 0o600

                new_private_key = Key.from_bind(new_private_filename)
                assert new_private_key.key_id() == key_from_bind.key_id()
                assert new_private_key.dnskey == key_from_bind.dnskey
                assert (
                    new_private_key.private.to_pem() == key_from_bind.private.to_pem()
                )
                assert new_private_key.public.to_pem() == key_from_bind.public.to_pem()

    @unittest.skipUnless(dns._features.have("jwk"), "jwcrypto required")
    def test_import_export_jwk_private_key(self):
        """Test importing and exporting JWK private keys."""

        for private_key_file in KEYS_DIRECTORY.glob("K*.private"):

            key_from_bind = Key.from_bind(private_key_file)

            key_from_jwk = Key.from_jwk_file(private_key_file.with_suffix(".json"))

            assert key_from_bind.dnskey == key_from_jwk.dnskey
            assert key_from_jwk.private.public_key().to_dnskey() == key_from_jwk.dnskey
            assert key_from_bind.private.to_pem() == key_from_jwk.private.to_pem()

            jwk_public_data = key_from_bind.to_jwk_text(public_only=True)
            key_from_public_jwk = Key.from_jwk_text(jwk_public_data)
            assert key_from_public_jwk.dnskey == key_from_bind.dnskey
            assert key_from_public_jwk.private is None

            # Write and read JWK-style private key file as binary
            with tempfile.NamedTemporaryFile("w+b", suffix=".json") as temp_file:
                key_from_bind.to_jwk_file(temp_file)
                temp_file.seek(0)
                read_jwk = Key.from_jwk_file(temp_file)
                assert read_jwk.name == key_from_bind.name
                assert read_jwk.dnskey == key_from_bind.dnskey
                assert read_jwk.private is not None
                assert key_from_bind.private is not None
                assert read_jwk.private.to_pem() == key_from_bind.private.to_pem()
                assert read_jwk.public.to_pem() == key_from_bind.public.to_pem()
                # windows ignores our mode bits
                if sys.platform != "win32":
                    stat = os.stat(temp_file.name)
                    assert stat.st_mode & 0o777 == 0o600

            # Write and read JWK-style private file as text
            with tempfile.NamedTemporaryFile("w+t", suffix=".json") as temp_file:
                key_from_bind.to_jwk_file(temp_file)
                temp_file.seek(0)
                read_jwk = Key.from_jwk_file(temp_file)
                assert read_jwk.name == key_from_bind.name
                assert read_jwk.dnskey == key_from_bind.dnskey
                assert read_jwk.private is not None
                assert key_from_bind.private is not None
                assert read_jwk.private.to_pem() == key_from_bind.private.to_pem()
                assert read_jwk.public.to_pem() == key_from_bind.public.to_pem()
                # windows ignores our mode bits
                if sys.platform != "win32":
                    stat = os.stat(temp_file.name)
                    assert stat.st_mode & 0o777 == 0o600

            # Write and read JWK-style public key file as binary
            with tempfile.TemporaryDirectory() as temp_dir:
                new_private_filename = key_from_bind.to_bind(
                    Path(temp_dir)
                ).with_suffix(".json")
                key_from_bind.to_jwk_file(new_private_filename, public_only=True)
                read_jwk = Key.from_jwk_file(new_private_filename)
                assert read_jwk.name == key_from_bind.name
                assert read_jwk.dnskey == key_from_bind.dnskey
                assert read_jwk.private is None
                assert read_jwk.public.to_pem() == key_from_bind.public.to_pem()
                stat = os.stat(new_private_filename)
                assert stat.st_mode & 0o444 == 0o444

    @unittest.skipUnless(dns._features.have("jwk"), "jwcrypto required")
    def test_bind_jwk_match(self):
        """Test that a key imported from a BIND private key matches the corresponding JWK."""

        for private_key_file in KEYS_DIRECTORY.glob("K*.private"):

            jwk_filename = private_key_file.with_suffix(".json")

            key_from_jwk = Key.from_jwk_file(jwk_filename)
            key_from_bind = Key.from_bind(private_key_file)

            assert key_from_bind.name == key_from_jwk.name
            assert key_from_bind.private.to_pem() == key_from_jwk.private.to_pem()
            assert key_from_bind.public.to_pem() == key_from_jwk.public.to_pem()
            assert key_from_bind.dnskey == key_from_jwk.dnskey

    def test_bind_private_key_dnskey_mismatch(self):
        """Test that a BIND private key with a mismatched DNSKEY raises an error."""

        for private_key_file in KEYS_DIRECTORY.glob("K*.private"):
            key_from_bind = Key.from_bind(private_key_file)
            algorithm_cls = get_algorithm_cls(key_from_bind.dnskey.algorithm)

            if issubclass(algorithm_cls, PrivateRSA):
                other_private_key = algorithm_cls.generate(key_size=2048)
            else:
                other_private_key = algorithm_cls.generate()
            other_dnskey = other_private_key.public_key().to_dnskey(
                flags=key_from_bind.dnskey.flags
            )

            with open(private_key_file, "rb") as fp:
                private_data = fp.read()
            public_data = f"{key_from_bind.name} IN DNSKEY {other_dnskey}\n".encode()

            with self.assertRaises((dns.exception.InvalidKeyFormat, ValueError)):
                Key.from_bind_bytes(private_data=private_data, public_data=public_data)

    def test_key_to_ds(self):
        """Test that the DS record generated from a key matches the expected value."""

        private_key = PrivateED25519.generate()
        public_key = private_key.public_key()
        dnskey = public_key.to_dnskey()
        key = Key(
            name=dns.name.from_text("example.com"),
            private=private_key,
            public=public_key,
            dnskey=dnskey,
        )
        algorithm = "SHA256"
        assert key.to_ds(algorithm=algorithm) == dns.dnssec.make_ds(
            name=key.name, key=dnskey, algorithm=algorithm
        )

    def test_from_dnskey(self):
        name = dns.name.from_text("example.com")
        dnskey = dns.dnssec.make_dnskey(
            public_key=PrivateED25519.generate().public_key(),
            algorithm=Algorithm.ED25519,
            flags=256,
            protocol=3,
        )

        key = Key.from_dnskey(name, dnskey)
        self.assertEqual(key.name, name)
        self.assertEqual(key.dnskey, dnskey)
        self.assertIsNone(key.private)

    def test_from_dnskey_text_name(self):
        dnskey = PrivateED25519.generate().public_key().to_dnskey()
        key = Key.from_dnskey("example.com", dnskey)
        self.assertEqual(key.name, dns.name.from_text("example.com"))
        self.assertEqual(key.key_id(), dns.dnssec.key_id(dnskey))
        self.assertIsNone(key.private)

    def test_relative_name_rejected(self):
        private_key = PrivateED25519.generate()
        public_key = private_key.public_key()
        with self.assertRaises(ValueError):
            Key(
                name=dns.name.from_text("example", None),
                private=private_key,
                public=public_key,
                dnskey=public_key.to_dnskey(),
            )

    def _copy_bind_key(self, directory, private_name, public_text=None):
        """Copy the ED25519 test key into *directory* as *private_name*,
        optionally replacing the public key file contents."""

        source = KEYS_DIRECTORY / "Kexample.com.+015+63713.private"
        private_filename = Path(directory) / private_name
        private_filename.write_bytes(source.read_bytes())
        if public_text is None:
            public_text = source.with_suffix(".key").read_text()
        private_filename.with_suffix(".key").write_text(public_text)
        return private_filename

    def test_from_bind_invalid_filename(self):
        """Test that a key with an invalid filename raises an error."""

        with tempfile.TemporaryDirectory() as temp_dir:
            private_filename = self._copy_bind_key(temp_dir, "example.com.private")
            with self.assertRaisesRegex(
                dns.exception.InvalidKeyFormat, "Invalid private key filename"
            ):
                Key.from_bind(private_filename)

    def test_from_bind_name_mismatch(self):
        """Test that a key with a mismatched name raises an error."""

        with tempfile.TemporaryDirectory() as temp_dir:
            private_filename = self._copy_bind_key(
                temp_dir, "Kexample.org.+015+63713.private"
            )
            with self.assertRaisesRegex(
                dns.exception.InvalidKeyFormat, "Key name mismatch"
            ):
                Key.from_bind(private_filename)

    def test_from_bind_algorithm_mismatch(self):
        """Test that a key with a mismatched algorithm raises an error."""

        with tempfile.TemporaryDirectory() as temp_dir:
            private_filename = self._copy_bind_key(
                temp_dir, "Kexample.com.+013+63713.private"
            )
            with self.assertRaisesRegex(
                dns.exception.InvalidKeyFormat, "Algorithm mismatch"
            ):
                Key.from_bind(private_filename)

    def test_from_bind_key_id_mismatch(self):
        """Test that a key with a mismatched key ID raises an error."""

        with tempfile.TemporaryDirectory() as temp_dir:
            private_filename = self._copy_bind_key(
                temp_dir, "Kexample.com.+015+00001.private"
            )
            with self.assertRaisesRegex(
                dns.exception.InvalidKeyFormat, "Key ID mismatch"
            ):
                Key.from_bind(private_filename)

    def test_from_bind_mixed_case_name(self):
        """A mixed-case owner name matches a lowercase filename."""

        public_text = (
            "Example.COM. IN DNSKEY 256 3 15 "
            "xX2gT6qJ76coFM3/pAUBxfBZYGnfSZqbNvbZFI428Ao=\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            private_filename = self._copy_bind_key(
                temp_dir, "Kexample.com.+015+63713.private", public_text
            )
            key = Key.from_bind(private_filename)
            self.assertEqual(key.name, dns.name.from_text("example.com"))
            self.assertEqual(key.key_id(), 63713)
            self.assertEqual(
                key.get_bind_private_key_filename(),
                Path("Kexample.com.+015+63713.private"),
            )

    def test_to_bind_public_only(self):
        """Test that a key without a private key can only be written public-only."""

        dnskey = PrivateED25519.generate().public_key().to_dnskey()
        key = Key.from_dnskey("example.com", dnskey)

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)

            # A key without a private key can only be written public-only
            with self.assertRaises(dns.exception.InvalidKeyFormat):
                key.to_bind(directory)

            public_filename = key.to_bind(directory, public_only=True)
            self.assertEqual(
                public_filename, directory / key.get_bind_public_key_filename()
            )
            self.assertEqual(
                [p.name for p in directory.iterdir()], [public_filename.name]
            )
            # The file has no TTL: "<name> IN DNSKEY <rdata>"
            owner, rdclass, rdtype, rdata = public_filename.read_text().split(
                maxsplit=3
            )
            rrset = dns.rrset.from_text(owner, 0, rdclass, rdtype, rdata)
            self.assertEqual(rrset.name, key.name)
            self.assertEqual(rrset[0], dnskey)

            with self.assertRaises(FileExistsError):
                key.to_bind(directory, public_only=True)
            self.assertEqual(
                key.to_bind(directory, public_only=True, overwrite=True),
                public_filename,
            )

    def test_to_bind_cleanup_on_failure(self):
        """Temporary files are removed and the original error is raised
        when writing fails."""

        key = Key.from_bind(KEYS_DIRECTORY / "Kexample.com.+015+63713.private")

        for overwrite in (False, True):
            for public_only in (False, True):
                with (
                    self.subTest(overwrite=overwrite, public_only=public_only),
                    tempfile.TemporaryDirectory() as temp_dir,
                    unittest.mock.patch(
                        "os.replace" if overwrite else "os.rename",
                        side_effect=OSError("boom"),
                    ),
                ):
                    with self.assertRaisesRegex(OSError, "boom"):
                        key.to_bind(
                            temp_dir, overwrite=overwrite, public_only=public_only
                        )
                    self.assertEqual(list(Path(temp_dir).iterdir()), [])

    def test_to_bind_cleanup_on_private_failure(self):
        """If only moving the private key file fails, its temporary file is
        removed and the original error is raised."""

        key = Key.from_bind(KEYS_DIRECTORY / "Kexample.com.+015+63713.private")
        real_rename = os.rename

        def rename(src, dst):
            if Path(dst).suffix == ".private":
                raise OSError("boom")
            real_rename(src, dst)

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            unittest.mock.patch("os.rename", side_effect=rename),
        ):
            with self.assertRaisesRegex(OSError, "boom"):
                key.to_bind(temp_dir)
            # The public key file was already in place; no temporary files remain
            self.assertEqual(
                [p.name for p in Path(temp_dir).iterdir()],
                [key.get_bind_public_key_filename().name],
            )

    def test_to_bind_private_key_exists(self):
        """Test that attempting to write a private key file that already exists raises an error."""

        key = Key.from_bind(KEYS_DIRECTORY / "Kexample.com.+015+63713.private")

        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            (directory / key.get_bind_private_key_filename()).touch()
            with self.assertRaisesRegex(FileExistsError, "Private key file"):
                key.to_bind(directory)

    def test_to_bind_filename_encoding(self):
        """Test that the BIND-style filenames are encoded and decoded correctly."""

        test_cases = [
            (".", "."),
            ("example.com.", "example.com."),
            ("räksmörgås.example.com", "xn--rksmrgs-5wao1o.example.com."),
            ("foo+bar.example.com", "foo%2Bbar.example.com."),
            ("foo/bar.example.com", "foo%2Fbar.example.com."),
            (b"b\x00rken.example.com", "b%00rken.example.com."),
        ]

        for decoded, encoded in test_cases:
            with self.subTest(decoded=decoded, encoded=encoded):
                assert _encode_name(dns.name.from_text(decoded)) == encoded
                assert _decode_name(encoded) == dns.name.from_text(decoded)

    def test_bind_filename_decoder_invalid(self):
        """Malformed names in filenames raise InvalidKeyFormat."""

        for bad in [
            "a..com.",
            ".com.",
            "..",
            "x" * 64 + ".com.",
            ("a" * 63 + ".") * 4,
        ]:
            with self.subTest(bad=bad):
                with self.assertRaises(dns.exception.InvalidKeyFormat):
                    _decode_name(bad)


if __name__ == "__main__":
    unittest.main()
