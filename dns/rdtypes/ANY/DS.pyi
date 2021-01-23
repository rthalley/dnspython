# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Optional

from dns.rdtypes.dsbase import DSBase
from dns.name import Name

class DS(DSBase):
    @classmethod
    def from_wire(cls, rdclass: int, rdtype: int, wire: bytes, current: int, rdlen: int, origin: Optional[Name] = None) -> 'DS': # type: ignore[override]
        ...
