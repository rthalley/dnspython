# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from dns.exception import SyntaxError

class BadTTL(SyntaxError): ...

def from_text(text: str) -> int: ...
