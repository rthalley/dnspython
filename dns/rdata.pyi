# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, BinaryIO, Dict, Optional, Tuple

from dns.name import Name, IDNACodec

class Rdata:
    def __init__(self) -> None:
        self.address : str
    def to_wire(self, file : Optional[BinaryIO], compress : Optional[Dict[Name,int]], origin : Optional[Name], canonicalize : Optional[bool]) -> Optional[bytes]:
        ...
    @classmethod
    def from_text(cls, rdclass : int, rdtype : int, tok: Any, origin: Optional[Name] = None, relativize: bool = True) -> Rdata:
        ...
_rdata_modules : Dict[Tuple[Any,Rdata],Any]

def from_text(rdclass : int, rdtype : int, tok : Optional[str], origin : Optional[Name] = None,
              relativize : bool = True, relativize_to : Optional[Name] = None,
              idna_codec : Optional[IDNACodec] = None) -> Rdata:
    ...

def from_wire(rdclass : int, rdtype : int, wire : bytes, current : int, rdlen : int, origin : Optional[Name] = None) -> Rdata:
    ...
