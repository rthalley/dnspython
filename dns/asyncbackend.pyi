# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

from types import TracebackType
from typing import Any, Dict, Optional, Type

try:
    from ssl import SSLContext
except ImportError:
    class SSLContext: ... # type: ignore

def get_backend(name: str) -> Backend:
    ...
def sniff() -> str:
    ...
def get_default_backend() -> Backend:
    ...
def set_default_backend(name: str) -> Backend:
    ...

class Socket:
    async def close(self) -> None:
        ...

    async def __aenter__(self) -> 'Socket':
        ...

    async def __aexit__(self, exc_type: Optional[Type[BaseException]],
                              exc_value: Optional[BaseException],
                              traceback: Optional[TracebackType]) -> None:
        ...

class DatagramSocket(Socket):
    async def sendto(self, what: bytes, destination: str, timeout: int) -> None:
        ...

    async def recvfrom(self, size: int, timeout: int) -> bytes:
        ...

class StreamSocket(Socket):
    async def sendall(self, what: bytes, destination: str, timeout: int) -> None:
        ...

    async def recv(self, size: int, timeout: int) -> bytes:
        ...

class Backend:
    def name(self) -> str:
        ...

    async def make_socket(self, af: Any, socktype: int, proto: int = 0,
                          source: Any = None, destination: Optional[str] = None, timeout: Optional[int] = None,
                          ssl_context: Optional[SSLContext] = None, server_hostname: Optional[str] = None) -> Socket:
        ...
