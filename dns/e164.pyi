# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Iterable, Optional

from dns.name import Name
from dns.resolver import Answer, Resolver

def from_e164(text : str, origin: Name = ...) -> Name:
    ...

def to_e164(name : Name, origin : Optional[Name] = None, want_plus_prefix: bool =True) -> str:
    ...

def query(number : str, domains : Iterable[str], resolver : Optional[Resolver] = None) -> Answer:
    ...
