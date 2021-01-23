# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, BinaryIO, Dict, Optional, Set

from dns.name import Name
from dns.tokenizer import Tokenizer
from dns.rdata import Rdata

SEP : int
REVOKE : int
ZONE : int

def flags_to_text_set(flags : int) -> Set[str]:
    ...

def flags_from_text_set(texts_set: Set[str]) -> int:
    ...

class DNSKEYBase(Rdata):
    def __init__(self, rdclass: int, rdtype: int, flags: int, protocol: int, algorithm: int, key: str) -> None:
        self.flags : int
        self.protocol : int
        self.key : str
        self.algorithm : int

    def to_text(self, origin: Optional[Name] = None, relativize: bool = True, **kw : Any) -> str:
        ...

    @classmethod
    def from_text(cls, rdclass: int, rdtype: int, tok: Tokenizer, origin: Optional[Name] = None, relativize: bool = True) -> DNSKEYBase:
        ...

    def to_wire(self, file : Optional[BinaryIO], compress : Optional[Dict[Name,int]], origin : Optional[Name], canonicalize : Optional[bool]) -> Optional[bytes]:
        ...

    @classmethod
    def from_wire(cls, rdclass: int, rdtype: int, wire: bytes, current: int, rdlen: int, origin: Optional[Name] = None) -> DNSKEYBase:
        ...

    def flags_to_text_set(self) -> Set[str]:
        ...
