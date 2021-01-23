# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Optional

from dns.rdtypes.dnskeybase import DNSKEYBase
from dns.name import Name

class DNSKEY(DNSKEYBase):
    @classmethod
    def from_wire(cls, rdclass: int, rdtype: int, wire: bytes, current: int, rdlen: int, origin: Optional[Name] = None) -> 'DNSKEY': # type: ignore[override]
        ...
