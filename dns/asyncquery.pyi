# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from typing import Dict, Optional

try:
    from ssl import SSLContext
except ImportError:
    class SSLContext: ... # type: ignore

from dns.asyncbackend import Backend, DatagramSocket, StreamSocket
from dns.message import Message

async def udp(q : Message, where : str,
              timeout : Optional[float] = None, port : int = 53,
              source : Optional[str] = None, source_port : Optional[int] = 0,
              ignore_unexpected : Optional[bool] = False,
              one_rr_per_rrset : Optional[bool] = False,
              ignore_trailing : Optional[bool] = False,
              sock : Optional[DatagramSocket] = None,
              backend : Optional[Backend] = None) -> Message:
    ...

async def tcp(q : Message, where : str, timeout : Optional[float] = None, port : int = 53,
        af : Optional[int] = None, source : Optional[str] = None,
        source_port : Optional[int] = 0,
        one_rr_per_rrset : Optional[bool] = False,
        ignore_trailing : Optional[bool] = False,
        sock : Optional[StreamSocket] = None,
        backend : Optional[Backend] = None) -> Message:
    ...

async def tls(q : Message, where : str,
              timeout : Optional[float] = None, port : int = 53,
              source : Optional[str] = None, source_port : Optional[int] = 0,
              one_rr_per_rrset : Optional[bool] = False,
              ignore_trailing : Optional[bool] = False,
              sock : Optional[StreamSocket] = None,
              backend : Optional[Backend] = None,
              ssl_context: Optional[SSLContext] = None,
              server_hostname: Optional[str] = None) -> Message:
    ...
