from abc import ABC, abstractmethod
from typing import Any, Optional, Type

from cryptography.hazmat.primitives import serialization

import dns.rdataclass
import dns.rdatatype
from dns.dnssectypes import Algorithm
from dns.exception import AlgorithmKeyMismatch
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag


class AlgorithmPublicKey(ABC):
    algorithm: Algorithm
    key: Any = None
    key_cls: Any = None

    def __init__(self, key: Any):
        if self.key_cls is None:
            raise TypeError("Undefined private key class")
        if not isinstance(key, self.key_cls):
            raise AlgorithmKeyMismatch
        self.key = key

    @abstractmethod
    def verify(self, signature: bytes, data: bytes) -> None:
        pass

    @abstractmethod
    def encode_key_bytes(self) -> bytes:
        pass

    def to_dnskey(self, flags: int = Flag.ZONE, protocol: int = 3) -> DNSKEY:
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
    def from_dnskey(cls, key: DNSKEY) -> "AlgorithmPublicKey":
        pass

    @classmethod
    def from_pem(cls, public_pem: bytes) -> "AlgorithmPublicKey":
        key = serialization.load_pem_public_key(public_pem)
        return cls(key=key)

    def to_pem(self) -> bytes:
        return self.key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class AlgorithmPrivateKey(ABC):
    public_cls: Type[AlgorithmPublicKey]
    key: Any = None
    key_cls: Any = None

    def __init__(self, key: Any):
        if self.key_cls is None:
            raise TypeError("Undefined private key class")
        if not isinstance(key, self.key_cls):
            raise AlgorithmKeyMismatch
        self.key = key

    @abstractmethod
    def sign(self, data: bytes, verify: bool = False) -> bytes:
        pass

    @abstractmethod
    def public_key(self) -> "AlgorithmPublicKey":
        pass

    @classmethod
    def from_pem(cls, private_pem: bytes, password: Optional[bytes] = None) -> "AlgorithmPrivateKey":
        key = serialization.load_pem_private_key(private_pem, password=password)
        return cls(key=key)

    def to_pem(self, password: Optional[bytes] = None) -> bytes:
        encryption_algorithm: serialization.KeySerializationEncryption
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()
        return self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )
