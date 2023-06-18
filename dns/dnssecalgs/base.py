from abc import ABC, abstractmethod
from typing import Optional, Type

import dns.rdataclass
import dns.rdatatype
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.dnskeybase import Flag


class GenericPublicKey(ABC):
    algorithm: Algorithm

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
    def from_dnskey(cls, key: DNSKEY) -> "GenericPublicKey":
        pass

    @classmethod
    @abstractmethod
    def from_pem(cls, public_pem: bytes) -> "GenericPublicKey":
        pass

    @abstractmethod
    def to_pem(self) -> bytes:
        pass


class GenericPrivateKey(ABC):
    public_cls: Type[GenericPublicKey]

    @abstractmethod
    def sign(self, data: bytes, verify: bool = False) -> bytes:
        pass

    @abstractmethod
    def public_key(self) -> "GenericPublicKey":
        pass

    @classmethod
    @abstractmethod
    def from_pem(
        cls, private_pem: bytes, password: Optional[bytes] = None
    ) -> "GenericPrivateKey":
        pass

    @abstractmethod
    def to_pem(self, password: Optional[bytes] = None) -> bytes:
        pass
