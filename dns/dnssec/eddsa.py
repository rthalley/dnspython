from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed448, ed25519

from dns.dnssec.algbase import AlgorithmPrivateKeyBase, AlgorithmPublicKeyBase
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


@dataclass
class PublicEDDSA(AlgorithmPublicKeyBase):
    def verify(self, signature: bytes, data: bytes):
        self.public_key.verify(signature, data)

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 8080, section 3."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )


@dataclass
class PrivateEDDSA(AlgorithmPrivateKeyBase):
    def sign(self, data: bytes, verify: bool = False) -> bytes:
        """Sign using a private key per RFC 8080, section 4."""
        signature = self.private_key.sign(data)
        if verify:
            self.private_key.public_key().verify(signature, data)
        return signature


@dataclass
class PublicED25519(PublicEDDSA):
    public_key: ed25519.Ed25519PublicKey
    algorithm = Algorithm.ED25519

    @classmethod
    def from_dnskey(cls, key: DNSKEY):
        return cls(
            public_key=ed25519.Ed25519PublicKey.from_public_bytes(key.key),
            algorithm=cls.algorithm,
        )


@dataclass
class PrivateED25519(PrivateEDDSA):
    private_key: ed25519.Ed25519PrivateKey
    public_cls = PublicED25519

    def public_key(self) -> "PublicED25519":
        return self.public_cls(
            public_key=self.private_key.public_key(),
            algorithm=self.public_cls.algorithm,
        )

    @classmethod
    def generate(cls):
        return cls(
            private_key=ed25519.Ed25519PrivateKey.generate(), public_cls=cls.public_cls
        )


@dataclass
class PublicED448(PublicEDDSA):
    public_key: ed448.Ed448PublicKey
    algorithm = Algorithm.ED448

    @classmethod
    def from_dnskey(cls, key: DNSKEY):
        return cls(
            public_key=ed448.Ed448PublicKey.from_public_bytes(key.key),
            algorithm=cls.algorithm,
        )


@dataclass
class PrivateED448(PrivateEDDSA):
    private_key: ed448.Ed448PrivateKey
    public_cls = PublicED448

    def public_key(self) -> "PublicED448":
        return self.public_cls(
            public_key=self.private_key.public_key(),
            algorithm=self.public_cls.algorithm,
        )

    @classmethod
    def generate(cls):
        return cls(
            private_key=ed448.Ed448PrivateKey.generate(), public_cls=cls.public_cls
        )
