# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from socket import socket
from typing import Any, Dict, Generator, Optional, Union

try:
    from ssl import SSLContext
except ImportError:
    class SSLContext: ... # type: ignore

from requests.sessions import Session

from dns.message import Message
from dns.name import Name
from dns.rdataclass import IN
from dns.rdatatype import AXFR
from dns.tsig import default_algorithm

have_doh: bool

def https(q : Message, where: str, timeout : Optional[float] = None,
          port : Optional[int] = 443, source : Optional[str] = None,
          source_port : Optional[int] = 0,
          session: Optional[Session] = None,
          path : Optional[str] = ..., post : Optional[bool] = True,
          bootstrap_address : Optional[str] = None,
          verify : Optional[bool] = True) -> Message:
    ...

def tcp(q : Message, where : str, timeout : Optional[float] = None, port : int = 53,
        af : Optional[int] = None, source : Optional[str] = None,
        source_port : Optional[int] = 0,
        one_rr_per_rrset : Optional[bool] = False,
        ignore_trailing : Optional[bool] = False,
        sock : Optional[socket] = None) -> Message:
    ...

def xfr(where : Optional[str], zone : Union[Name,str], rdtype: int = AXFR,
        rdclass: int = IN,
        timeout : Optional[float] = None, port: int = 53,
        keyring : Optional[Dict[Name, bytes]] = None,
        keyname : Union[str, Name, None]= None, relativize: bool = True,
        lifetime : Optional[float] = None,
        source : Optional[str] = None, source_port: int = 0, serial: int = 0,
        use_udp : Optional[bool] = False,
        keyalgorithm: Any = default_algorithm) \
        -> Generator[Any,Any,Message]:
    ...

def udp(q : Message, where : str, timeout : Optional[float] = None,
        port : int = 53, source : Optional[str] = None, source_port : Optional[int] = 0,
        ignore_unexpected : Optional[bool] = False,
        one_rr_per_rrset : Optional[bool] = False,
        ignore_trailing : Optional[bool] = False,
        sock : Optional[socket] = None) -> Message:
    ...

def tls(q : Message, where : str, timeout : Optional[float] = None,
        port : int = 53, source : Optional[str] = None, source_port : Optional[int] = 0,
        one_rr_per_rrset : Optional[bool] = False,
        ignore_trailing : Optional[bool] = False,
        sock : Optional[socket] = None,
        ssl_context: Optional[SSLContext] = None,
        server_hostname: Optional[str] = None) -> Message:
    ...
