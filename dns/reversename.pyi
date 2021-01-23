# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from dns.name import Name

def from_address(text : str) -> Name:
    ...

def to_address(name : Name) -> str:
    ...
