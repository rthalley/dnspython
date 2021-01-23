# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Dict

from dns.name import Name

def from_text(textring : Dict[str,str]) -> Dict[Name,bytes]:
    ...
def to_text(keyring : Dict[Name,bytes]) -> Dict[str, str]:
    ...
