# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""trio async I/O library query support"""

import socket
import trio
import trio.socket  # type: ignore

import dns._asyncbackend
import dns.exception


def _maybe_timeout(timeout):
    if timeout:
        return trio.move_on_after(timeout)
    else:
        return dns._asyncbackend.NullContext()


# for brevity
_lltuple = dns._asyncbackend.low_level_address_tuple


class DatagramSocket(dns._asyncbackend.DatagramSocket):
    def __init__(self, socket):
        self.socket = socket
        self.family = socket.family

    async def sendto(self, what, destination, timeout):
        with _maybe_timeout(timeout):
            return await self.socket.sendto(what, destination)
        raise dns.exception.Timeout(timeout=timeout)

    async def recvfrom(self, timeout):
        with _maybe_timeout(timeout):
            return await self.socket.recvfrom(65535)
        raise dns.exception.Timeout(timeout=timeout)

    async def close(self):
        self.socket.close()

    async def getpeername(self):
        return self.socket.getpeername()


class StreamSocket(dns._asyncbackend.DatagramSocket):
    def __init__(self, family, stream):
        self.family = family
        self.stream = stream

    async def sendall(self, what, timeout):
        with _maybe_timeout(timeout):
            return await self.stream.send_all(what)
        raise dns.exception.Timeout(timeout=timeout)

    async def recv(self, count, timeout):
        with _maybe_timeout(timeout):
            return await self.stream.receive_some(count)
        raise dns.exception.Timeout(timeout=timeout)

    async def close(self):
        await self.stream.aclose()

    async def getpeername(self):
        return self.stream.socket.getpeername()


class Backend(dns._asyncbackend.Backend):
    def name(self):
        return 'trio'

    async def make_socket(self, af, socktype, proto=0, source=None,
                          destination=None, timeout=None,
                          ssl_context=None, server_hostname=None):
        s = trio.socket.socket(af, socktype, proto)
        try:
            if source:
                await s.bind(_lltuple(af, source))
            if socktype == socket.SOCK_STREAM:
                with _maybe_timeout(timeout):
                    await s.connect(_lltuple(af, destination))
        except Exception:
            s.close()
            raise
        if socktype == socket.SOCK_DGRAM:
            return DatagramSocket(s)
        elif socktype == socket.SOCK_STREAM:
            return StreamSocket(af, trio.SocketStream(s))
        raise NotImplementedError(f'unsupported socket type {socktype}')

    async def sleep(self, interval):
        await trio.sleep(interval)
