# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, Dict, Tuple, Optional, Union

from dns.exception import DNSException
from dns.name import Name
from dns.node import Node
from dns.rdata import Rdata
from dns.rdataset import Rdataset
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rrset import RRset

_have_ecdsa : bool
_have_pycrypto : bool
_have_pyca : bool

def validate_rrsig(rrset : Union[Tuple[Name, Rdataset], RRset], rrsig : Rdata, keys : Dict[Name, Union[Node, Rdataset]], origin : Optional[Name] = None, now : Optional[int] = None) -> None:
    ...

def validate(rrset: Union[Tuple[Name, Rdataset], RRset], rrsigset : Union[Tuple[Name, Rdataset], RRset], keys : Dict[Name, Union[Node, Rdataset]], origin: Any = None, now: Any = None) -> None:
    ...

class ValidationFailure(DNSException):
    ...

def make_ds(name : Name, key : DNSKEY, algorithm : str, origin : Optional[Name] = None) -> DS:
    ...

def nsec3_hash(domain: str, salt: Optional[Union[str, bytes]], iterations: int, algo: int) -> str:
    ...
