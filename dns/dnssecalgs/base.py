from abc import ABC, abstractmethod
from typing import Any, Type

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
