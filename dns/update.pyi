# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, Dict, Optional, Union

from dns.message import Message
from dns.name import Name
from dns.rdataclass import IN
from dns.tsig import default_algorithm

class Update(Message):
    def __init__(self, zone : Union[Name, str], rdclass : Union[int,str] = IN, keyring : Optional[Dict[Name,bytes]] = None,
                 keyname : Optional[Name] = None, keyalgorithm : Optional[Name] = default_algorithm) -> None:
        self.id : int
    def add(self, name : Union[str,Name], *args : Any) -> None:
        ...
    def delete(self, name : Union[str,Name], *args : Any) -> None:
        ...
    def replace(self, name : Union[str,Name], *args : Any) -> None:
        ...
    def present(self, name : Union[str,Name], *args : Any) -> None:
        ...
    def absent(self, name : Union[str,Name], rdtype: Union[int, str, None] = None) -> None:
        ...
    def to_wire(self, origin : Optional[Name] = None, max_size: int = ..., **kw: Any) -> bytes:
        ...
