# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""asyncio library query support"""

import socket
import asyncio
import sys

import dns._asyncbackend
import dns.exception


_is_win32 = sys.platform == "win32"


def _get_running_loop():
    try:
        return asyncio.get_running_loop()
    except AttributeError:  # pragma: no cover
        return asyncio.get_event_loop()


class _DatagramProtocol:
    def __init__(self):
        self.transport = None
        self.recvfrom = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.recvfrom and not self.recvfrom.done():
            self.recvfrom.set_result((data, addr))

    def error_received(self, exc):  # pragma: no cover
        if self.recvfrom and not self.recvfrom.done():
            self.recvfrom.set_exception(exc)

    def connection_lost(self, exc):
        if self.recvfrom and not self.recvfrom.done():
            self.recvfrom.set_exception(exc)

    def close(self):
        self.transport.close()


async def _maybe_wait_for(awaitable, timeout):
    if timeout:
        try:
            return await asyncio.wait_for(awaitable, timeout)
        except asyncio.TimeoutError:
            raise dns.exception.Timeout(timeout=timeout)
    else:
        return await awaitable


class DatagramSocket(dns._asyncbackend.DatagramSocket):
    def __init__(self, family, transport, protocol):
        super().__init__(family)
        self.transport = transport
        self.protocol = protocol

    async def sendto(self, what, destination, timeout):  # pragma: no cover
        # no timeout for asyncio sendto
        self.transport.sendto(what, destination)
        return len(what)

    async def recvfrom(self, size, timeout):
        # ignore size as there's no way I know to tell protocol about it
        done = _get_running_loop().create_future()
        try:
            assert self.protocol.recvfrom is None
            self.protocol.recvfrom = done
            await _maybe_wait_for(done, timeout)
            return done.result()
        finally:
            self.protocol.recvfrom = None

    async def close(self):
        self.protocol.close()

    async def getpeername(self):
        return self.transport.get_extra_info("peername")

    async def getsockname(self):
        return self.transport.get_extra_info("sockname")

    async def getpeercert(self, timeout):
        raise NotImplementedError


class StreamSocket(dns._asyncbackend.StreamSocket):
    def __init__(self, af, reader, writer):
        self.family = af
        self.reader = reader
        self.writer = writer

    async def sendall(self, what, timeout):
        self.writer.write(what)
        return await _maybe_wait_for(self.writer.drain(), timeout)

    async def recv(self, size, timeout):
        return await _maybe_wait_for(self.reader.read(size), timeout)

    async def close(self):
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except AttributeError:  # pragma: no cover
            pass

    async def getpeername(self):
        return self.writer.get_extra_info("peername")

    async def getsockname(self):
        return self.writer.get_extra_info("sockname")

    async def getpeercert(self, timeout):
        return self.writer.get_extra_info("peercert")


try:
    import anyio
    import httpx

    import httpcore
    import httpcore.backends.base
    import httpcore.backends.asyncio

    from dns.query import _compute_times, _remaining, _expiration_for_this_attempt

    class _NetworkBackend(httpcore.backends.base.AsyncNetworkBackend):
        def __init__(self, resolver, local_port, bootstrap_address, family):
            super().__init__()
            self._local_port = local_port
            self._resolver = resolver
            self._bootstrap_address = bootstrap_address
            self._family = family
            if local_port != 0:
                raise NotImplementedError(
                    "the asyncio transport for HTTPX cannot set the local port"
                )

        async def connect_tcp(
            self, host, port, timeout, local_address
        ):  # pylint: disable=signature-differs
            addresses = []
            _, expiration = _compute_times(timeout)
            if dns.inet.is_address(host):
                addresses.append(host)
            elif self._bootstrap_address is not None:
                addresses.append(self._bootstrap_address)
            else:
                timeout = _remaining(expiration)
                family = self._family
                if local_address:
                    family = dns.inet.af_for_address(local_address)
                answers = await self._resolver.resolve_name(
                    host, family=family, lifetime=timeout
                )
                addresses = answers.addresses()
            for address in addresses:
                try:
                    attempt_expiration = _expiration_for_this_attempt(2.0, expiration)
                    timeout = _remaining(attempt_expiration)
                    with anyio.fail_after(timeout):
                        stream = await anyio.connect_tcp(
                            remote_host=address,
                            remote_port=port,
                            local_host=local_address,
                        )
                    return httpcore.backends.asyncio.AsyncIOStream(stream)
                except Exception:
                    pass
            raise httpcore.ConnectError

        async def connect_unix_socket(
            self, path, timeout
        ):  # pylint: disable=signature-differs
            raise NotImplementedError

        async def sleep(self, seconds):  # pylint: disable=signature-differs
            await anyio.sleep(seconds)

    class _HTTPTransport(httpx.AsyncHTTPTransport):
        def __init__(
            self,
            *args,
            local_port=0,
            bootstrap_address=None,
            resolver=None,
            family=socket.AF_UNSPEC,
            **kwargs,
        ):
            if resolver is None:
                # pylint: disable=import-outside-toplevel,redefined-outer-name
                import dns.asyncresolver

                resolver = dns.asyncresolver.Resolver()
            super().__init__(*args, **kwargs)
            self._pool._network_backend = _NetworkBackend(
                resolver, local_port, bootstrap_address, family
            )

except ImportError:
    _HTTPTransport = dns._asyncbackend.NullTransport  # type: ignore


class Backend(dns._asyncbackend.Backend):
    def name(self):
        return "asyncio"

    async def make_socket(
        self,
        af,
        socktype,
        proto=0,
        source=None,
        destination=None,
        timeout=None,
        ssl_context=None,
        server_hostname=None,
    ):
        if destination is None and socktype == socket.SOCK_DGRAM and _is_win32:
            raise NotImplementedError(
                "destinationless datagram sockets "
                "are not supported by asyncio "
                "on Windows"
            )
        loop = _get_running_loop()
        if socktype == socket.SOCK_DGRAM:
            transport, protocol = await loop.create_datagram_endpoint(
                _DatagramProtocol,
                source,
                family=af,
                proto=proto,
                remote_addr=destination,
            )
            return DatagramSocket(af, transport, protocol)
        elif socktype == socket.SOCK_STREAM:
            if destination is None:
                # This shouldn't happen, but we check to make code analysis software
                # happier.
                raise ValueError("destination required for stream sockets")
            (r, w) = await _maybe_wait_for(
                asyncio.open_connection(
                    destination[0],
                    destination[1],
                    ssl=ssl_context,
                    family=af,
                    proto=proto,
                    local_addr=source,
                    server_hostname=server_hostname,
                ),
                timeout,
            )
            return StreamSocket(af, r, w)
        raise NotImplementedError(
            "unsupported socket " + f"type {socktype}"
        )  # pragma: no cover

    async def sleep(self, interval):
        await asyncio.sleep(interval)

    def datagram_connection_required(self):
        return _is_win32

    def get_transport_class(self):
        return _HTTPTransport
