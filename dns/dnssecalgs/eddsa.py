from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

from dns.dnssecalgs.base import AlgorithmPrivateKeyBase, AlgorithmPublicKeyBase
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


@dataclass
class PublicEDDSA(AlgorithmPublicKeyBase):
    def verify(self, signature: bytes, data: bytes):
        self.key.verify(signature, data)

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 8080, section 3."""
        return self.key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )


@dataclass
class PrivateEDDSA(AlgorithmPrivateKeyBase):
    def sign(self, data: bytes, verify: bool = False) -> bytes:
        """Sign using a private key per RFC 8080, section 4."""
        signature = self.key.sign(data)
        if verify:
            self.key.public_key().verify(signature, data)
        return signature


@dataclass
class PublicED25519(PublicEDDSA):
    key: ed25519.Ed25519PublicKey
    algorithm = Algorithm.ED25519
    key_cls = ed25519.Ed25519PublicKey

    @classmethod
    def from_dnskey(cls, key: DNSKEY):
        return cls(
            key=ed25519.Ed25519PublicKey.from_public_bytes(key.key),
            algorithm=cls.algorithm,
        )


@dataclass
class PrivateED25519(PrivateEDDSA):
    key: ed25519.Ed25519PrivateKey
    public_cls = PublicED25519
    key_cls = ed25519.Ed25519PrivateKey

    def public_key(self) -> "PublicED25519":
        return self.public_cls(
            key=self.key.public_key(),
            algorithm=self.public_cls.algorithm,
        )

    @classmethod
    def generate(cls):
        return cls(
            key=ed25519.Ed25519PrivateKey.generate(), public_cls=cls.public_cls
        )


@dataclass
class PublicED448(PublicEDDSA):
    key: ed448.Ed448PublicKey
    algorithm = Algorithm.ED448
    key_cls = ed448.Ed448PublicKey

    @classmethod
    def from_dnskey(cls, key: DNSKEY):
        return cls(
            key=ed448.Ed448PublicKey.from_public_bytes(key.key),
            algorithm=cls.algorithm,
        )


@dataclass
class PrivateED448(PrivateEDDSA):
    key: ed448.Ed448PrivateKey
    public_cls = PublicED448
    key_cls = ed448.Ed448PrivateKey

    def public_key(self) -> "PublicED448":
        return self.public_cls(
            key=self.key.public_key(),
            algorithm=self.public_cls.algorithm,
        )

    @classmethod
    def generate(cls):
        return cls(
            key=ed448.Ed448PrivateKey.generate(), public_cls=cls.public_cls
        )
