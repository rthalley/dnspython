from typing import Union, Optional, List, Any, Dict
from .. import exception, rdataclass, name, rdatatype

def resolve(qname : str, rdtype : Union[int,str] = 0,
            rdclass : Union[int,str] = 0,
            tcp=False, source=None, raise_on_no_answer=True,
            source_port=0, search : Optional[bool]=None):
    ...

def resolve_address(self, ipaddr: str, *args: Any, **kwargs: Optional[Dict]):
    ...

def zone_for_name(name, rdclass : int = rdataclass.IN, tcp=False,
                  resolver : Optional[Resolver] = None):
    ...

class Resolver:
    def __init__(self, filename : Optional[str] = '/etc/resolv.conf',
                 configure : Optional[bool] = True):
        self.nameservers : List[str]
    def resolve(self, qname : str, rdtype : Union[int,str] = rdatatype.A,
                rdclass : Union[int,str] = rdataclass.IN,
                tcp : bool = False, source : Optional[str] = None,
                raise_on_no_answer=True, source_port : int = 0,
                 search : Optional[bool]=None):
        ...
