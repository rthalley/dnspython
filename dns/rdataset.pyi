# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, BinaryIO, Dict, List, Optional, Union

from dns.exception import DNSException
from dns.name import Name, IDNACodec
from dns.rdata import Rdata
from dns.rdatatype import NONE
from dns.set import Set

class DifferingCovers(DNSException):
    ...

class IncompatibleTypes(DNSException):
    ...

class Rdataset(Set):
    def __init__(self, rdclass: int, rdtype: int, covers: int = NONE, ttl: int = 0):
        self.rdclass : int = rdclass
        self.rdtype : int = rdtype
        self.covers : int = covers
        self.ttl : int = ttl

    def update_ttl(self, ttl : int) -> None:
        ...

    def add(self, rd : Rdata, ttl : Optional[int] =None) -> None:
        ...

    def union_update(self, other : Rdataset) -> None:
        ...

    def intersection_update(self, other : Rdataset) -> None:
        ...

    def update(self, other : Rdataset) -> None:
        ...

    def to_text(self, name : Optional[Name] =None, origin : Optional[Name] =None, relativize: bool = True,
                override_rdclass : Optional[int] =None, **kw: Any) -> bytes:
        ...

    def to_wire(self, name : Optional[Name], file : BinaryIO, compress : Optional[Dict[Name, int]] = None, origin : Optional[Name] = None,
                override_rdclass : Optional[int] = None, want_shuffle: bool = True) -> int:
        ...

    def match(self, rdclass : int, rdtype : int, covers : int) -> bool:
        ...


def from_text_list(rdclass : Union[int,str], rdtype : Union[int,str], ttl : int, text_rdatas : str, idna_codec : Optional[IDNACodec] = None) -> Rdataset:
    ...

def from_text(rdclass : Union[int,str], rdtype : Union[int,str], ttl : int, *text_rdatas : str) -> Rdataset:
    ...

def from_rdata_list(ttl : int, rdatas : List[Rdata]) -> Rdataset:
    ...

def from_rdata(ttl : int, *rdatas : List[Rdata]) -> Rdataset:
    ...
