# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, List, Optional, Union

from dns.name import Name
from dns.rdataset import Rdataset
from dns.rdatatype import NONE

class Node:
    def __init__(self) -> None:
        self.rdatasets : List[Rdataset]
    def to_text(self, name : Union[str,Name], **kw: Any) -> str:
        ...
    def find_rdataset(self, rdclass : int, rdtype : int, covers: int = NONE,
                      create: bool = False) -> Rdataset:
        ...
    def get_rdataset(self, rdclass : int, rdtype : int, covers: int = NONE,
                     create: bool = False) -> Optional[Rdataset]:
        ...
    def delete_rdataset(self, rdclass : int, rdtype : int, covers: int = NONE) -> None:
        ...
    def replace_rdataset(self, replacement : Rdataset) -> None:
        ...
