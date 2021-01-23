# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, BinaryIO, Dict, Optional

from dns.rdata import Rdata
from dns.name import Name

class TXTBase(Rdata):
    def _to_wire(self, file : Optional[BinaryIO], compress : Optional[Dict[Name,int]], origin : Optional[Name], canonicalize : bool) -> bytes: ... # pylint: disable=signature-differs
    @classmethod
    def from_text(cls, rdclass : int, rdtype : int, tok: Any, origin: Optional[Name] = None, relativize: bool = True, relativize_to: Optional[Name] = None) -> 'TXTBase': ...
    @classmethod
    def from_wire(cls, rdclass: int, rdtype: int, wire: bytes, current: int, rdlen: int, origin: Optional[Name] = None) -> 'TXTBase': # type: ignore[override]
        ...
    def to_text(self, origin : Optional[Name] = None, relativize : bool = True, **kw : Any) -> str:
        ...

class TXT(TXTBase):
    ...
