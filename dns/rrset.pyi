# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Optional

from dns.rdataset import Rdataset
from dns.rdatatype import NONE

class RRset(Rdataset):
    def __init__(self, name: str, rdclass : int , rdtype : int, covers: int = NONE,
                 deleting : Optional[int] = None) -> None:
        self.name = name
        self.deleting = deleting

def from_text(name : str, ttl : int, rdclass : str, rdtype : str, *text_rdatas : str) -> RRset:
    ...
