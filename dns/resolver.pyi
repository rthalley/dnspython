# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from socket import gethostbyname as _gethostbyname
from typing import Any, Iterable, Iterator, List, Optional, Tuple, Union

from dns.exception import DNSException, Timeout
from dns.message import Message
from dns.name import Name
from dns.rdataclass import IN
from dns.rdatatype import A

class NXDOMAIN(DNSException): ...
class YXDOMAIN(DNSException): ...
class NoAnswer(DNSException): ...
class NoNameservers(DNSException): ...
class NotAbsolute(DNSException): ...
class NoRootSOA(DNSException): ...
class NoMetaqueries(DNSException): ...
class NoResolverConfiguration(DNSException): ...

default_resolver: Optional[Resolver]

def get_default_resolver() -> Resolver: ...

def resolve(qname : str, rdtype : Union[int,str] = 0,
            rdclass : Union[int,str] = 0,
            tcp : bool = False, source : Any = None, raise_on_no_answer: bool = True,
            source_port : int = 0, lifetime : Optional[float]=None,
            search : Optional[bool]=None) -> Answer:
    ...
def query(qname : str, rdtype : Union[int,str] = 0,
          rdclass : Union[int,str] = 0,
            tcp : bool = False, source : Any = None, raise_on_no_answer: bool = True,
            source_port : int = 0, lifetime : Optional[float]=None) -> Answer:
    ...
def resolve_address(ipaddr: str, *args: Any, **kwargs: Any) -> Answer:
    ...
class LRUCache:
    def __init__(self, max_size: int = 1000) -> None:
        ...
    def get(self, key: Tuple[Name, int, int]) -> Optional[Answer]:
        ...
    def put(self, key: Tuple[Name, int, int], val: Answer) -> None:
        ...
class Answer(Iterable[Any]):
    def __init__(self, qname: str, rdtype: Union[int,str], rdclass: Union[int,str], response: Message,
                 raise_on_no_answer: bool = True) -> None:
        ...
    def __iter__(self) -> Iterator[Any]:
        ...
def zone_for_name(name: str, rdclass : int = IN, tcp: bool = False, resolver : Optional[Resolver] = None) -> Name:
    ...

class Resolver:
    def __init__(self, filename: str = ..., configure: bool = True) -> None:
        self.nameservers : List[str]
    def resolve(self, qname : str, rdtype : Union[int,str] = A,
                rdclass : Union[int,str] = IN,
                tcp : bool = False, source : Optional[str] = None,
                raise_on_no_answer : bool = True, source_port : int = 0,
                lifetime : Optional[float]=None,
                search : Optional[bool]=None) -> Answer:
        ...
    def query(self, qname : str, rdtype : Union[int,str] = A,
              rdclass : Union[int,str] = IN,
              tcp : bool = False, source : Optional[str] = None,
              raise_on_no_answer : bool = True, source_port : int = 0,
              lifetime : Optional[float]=None) -> Answer:
        ...
