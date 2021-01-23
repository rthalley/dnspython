# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Any, List, Optional, Union

from dns.asyncbackend import Backend
from dns.rdatatype import A
from dns.rdataclass import IN
from dns.resolver import Answer

async def resolve(qname : str, rdtype : Union[int,str] = 0,
                  rdclass : Union[int,str] = 0,
                  tcp : bool = False, source : Any = None, raise_on_no_answer : bool = True,
                  source_port : int = 0, lifetime : Optional[float]=None,
                  search : Optional[bool]=None,
                  backend : Optional[Backend]=None) -> Answer:
    ...
async def resolve_address(ipaddr: str, *args: Any, **kwargs: Any) -> Answer:
    ...

class Resolver:
    def __init__(self, filename : Optional[str] = ...,
                 configure : Optional[bool] = True) -> None:
        self.nameservers : List[str]
    async def resolve(self, qname : str, rdtype : Union[int,str] = A,
                      rdclass : Union[int,str] = IN,
                      tcp : bool = False, source : Optional[str] = None,
                      raise_on_no_answer : bool = True, source_port : int = 0,
                      lifetime : Optional[float]=None,
                      search : Optional[bool]=None,
                      backend : Optional[Backend]=None) -> Answer:
        ...
