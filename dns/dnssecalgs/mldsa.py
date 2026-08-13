from typing import Type

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from dns.dnssecalgs.cryptography import CryptographyPrivateKey, CryptographyPublicKey
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


class PublicMLDSA(CryptographyPublicKey):
    def verify(self, signature: bytes, data: bytes) -> None:
        self.key.verify(signature, data)

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per draft-westerbaan-dnssec-mldsa, section 3."""
        return self.key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    @classmethod
    def from_dnskey(cls, key: DNSKEY) -> "PublicMLDSA":
        cls._ensure_algorithm_key_combination(key)
        return cls(
            key=cls.key_cls.from_public_bytes(key.key),
        )


class PrivateMLDSA(CryptographyPrivateKey):
    public_cls: Type[PublicMLDSA]

    def sign(
        self,
        data: bytes,
        verify: bool = False,
        deterministic: bool = True,
    ) -> bytes:
        """Sign using a private key per draft-westerbaan-dnssec-mldsa, section 4."""
        signature = self.key.sign(data)
        if verify:
            self.public_key().verify(signature, data)
        return signature

    @classmethod
    def generate(cls) -> "PrivateMLDSA":
        return cls(key=cls.key_cls.generate())


class PublicMLDSA44(PublicMLDSA):
    key: mldsa.MLDSA44PublicKey
    key_cls = mldsa.MLDSA44PublicKey
    algorithm = Algorithm.MLDSA44


class PrivateMLDSA44(PrivateMLDSA):
    key: mldsa.MLDSA44PrivateKey
    key_cls = mldsa.MLDSA44PrivateKey
    public_cls = PublicMLDSA44
