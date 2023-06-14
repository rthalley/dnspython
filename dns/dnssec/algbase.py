from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import dns.rdataclass
import dns.rdatatype
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag


@dataclass
class AlgorithmPublicKeyBase(ABC):
    algorithm: Algorithm
    key_cls = None

    @abstractmethod
    def verify(self, signature: bytes, data: bytes) -> None:
        pass

    @abstractmethod
    def encode_key_bytes(self) -> bytes:
        pass

    def to_dnskey(self, flags: int = Flag.ZONE, protocol: int = 3):
        return DNSKEY(
            rdclass=dns.rdataclass.IN,
            rdtype=dns.rdatatype.DNSKEY,
            flags=flags,
            protocol=protocol,
            algorithm=self.algorithm,
            key=self.encode_key_bytes(),
        )

    @classmethod
    @abstractmethod
    def from_dnskey(cls, key: DNSKEY):
        pass

    @classmethod
    def from_key(cls, key: Any):
        """Return PublicKey from cryptography public key"""
        if cls.key_cls is None:
            raise TypeError("Unknown public key class: " + str(type(key)))
        if not isinstance(key, cls.key_cls):
            raise TypeError("Public key class mismatch: " + str(type(key)))
        return cls(public_key=key, algorithm=cls.algorithm)


@dataclass
class AlgorithmPrivateKeyBase(ABC):
    public_cls: AlgorithmPublicKeyBase
    key_cls = None

    @abstractmethod
    def sign(self, data: bytes, verify: bool = False) -> bytes:
        pass

    @abstractmethod
    def public_key(self) -> "AlgorithmPublicKeyBase":
        pass

    @classmethod
    def from_key(cls, key: Any):
        """Return PrivateKey from cryptography private key"""
        if cls.key_cls is None:
            raise TypeError("Unknown private key class: " + str(type(key)))
        if not isinstance(key, cls.key_cls):
            raise TypeError("Private key class mismatch: " + str(type(key)))
        return cls(private_key=key, public_cls=cls.public_cls)
