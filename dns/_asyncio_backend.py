# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""asyncio library query support"""

import asyncio
import socket
import sys

import dns._asyncbackend
import dns._features
import dns.exception
import dns.inet

_is_win32 = sys.platform == "win32"


def _get_running_loop():
    try:
        return asyncio.get_running_loop()
    except AttributeError:  # pragma: no cover
        return asyncio.get_event_loop()


class _DatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None
        self.recvq = asyncio.Queue()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.recvq.put_nowait((data, addr))

    def error_received(self, exc):
        self.recvq.put_nowait(exc)

    def connection_lost(self, exc):
        if exc is None:
            self.recvq.put_nowait(EOFError("EOF"))
        else:
            self.recvq.put_nowait(exc)

    def close(self):
        if self.transport is not None:
            self.transport.close()


async def _maybe_wait_for(awaitable, timeout):
    if timeout is not None:
        try:
            return await asyncio.wait_for(awaitable, timeout)
        except asyncio.TimeoutError:
            raise dns.exception.Timeout(timeout=timeout)
    else:
        return await awaitable


class _DatagramSocket(dns._asyncbackend.DatagramSocket):
    def __init__(self, family, transport, protocol):
        super().__init__(family, socket.SOCK_DGRAM)
        self.transport = transport
        self.protocol = protocol

    async def sendto(self, what, destination, timeout):  # pragma: no cover
        # no timeout for asyncio sendto
        self.transport.sendto(what, destination)
        return len(what)

    async def recvfrom(self, size, timeout):
        # ignore size as there's no way I know to tell protocol about it
        pkg = await _maybe_wait_for(self.protocol.recvq.get(), timeout)
        if isinstance(pkg, BaseException):
            raise pkg
        return pkg

    async def close(self):
        self.protocol.close()

    async def getpeername(self):
        return self.transport.get_extra_info("peername")

    async def getsockname(self):
        return self.transport.get_extra_info("sockname")

    async def getpeercert(self, timeout):
        raise NotImplementedError


class _StreamSocket(dns._asyncbackend.StreamSocket):
    def __init__(self, af, reader, writer):
        super().__init__(af, socket.SOCK_STREAM)
        self.reader = reader
        self.writer = writer

    async def sendall(self, what, timeout):
        self.writer.write(what)
        return await _maybe_wait_for(self.writer.drain(), timeout)

    async def recv(self, size, timeout):
        return await _maybe_wait_for(self.reader.read(size), timeout)

    async def close(self):
        self.writer.close()

    async def getpeername(self):
        return self.writer.get_extra_info("peername")

    async def getsockname(self):
        return self.writer.get_extra_info("sockname")

    async def getpeercert(self, timeout):
        return self.writer.get_extra_info("peercert")


if dns._features.have("doh"):
    import anyio
    import httpcore
    import httpcore._backends.anyio
    import httpx

    _CoreAsyncNetworkBackend = httpcore.AsyncNetworkBackend
    _CoreAnyIOStream = httpcore._backends.anyio.AnyIOStream  # pyright: ignore

    from dns.query import _compute_times, _expiration_for_this_attempt, _remaining

    class _NetworkBackend(_CoreAsyncNetworkBackend):
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
            self, host, port, timeout=None, local_address=None, socket_options=None
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
                    return _CoreAnyIOStream(stream)
                except Exception:
                    pass
            raise httpcore.ConnectError

        async def connect_unix_socket(
            self, path, timeout=None, socket_options=None
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
            if resolver is None and bootstrap_address is None:
                # pylint: disable=import-outside-toplevel,redefined-outer-name
                import dns.asyncresolver

                resolver = dns.asyncresolver.Resolver()
            super().__init__(*args, **kwargs)
            self._pool._network_backend = _NetworkBackend(  # type: ignore
                resolver, local_port, bootstrap_address, family
            )

else:
    _HTTPTransport = dns._asyncbackend.NullTransport  # pyright: ignore


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
        loop = _get_running_loop()
        if socktype == socket.SOCK_DGRAM:
            if _is_win32 and source is None:
                # Win32 wants explicit binding before recvfrom().  This is the
                # proper fix for [#637].
                source = (dns.inet.any_for_af(af), 0)
            transport, protocol = await loop.create_datagram_endpoint(
                _DatagramProtocol,  # pyright: ignore
                local_addr=source,
                family=af,
                proto=proto,
                remote_addr=destination,
            )
            return _DatagramSocket(af, transport, protocol)
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
            return _StreamSocket(af, r, w)
        raise NotImplementedError(
            "unsupported socket " + f"type {socktype}"
        )  # pragma: no cover

    async def serve(
        self,
        client_connected_cb,
        af,
        socktype,
        addr,
    ):
        if socktype == socket.SOCK_DGRAM:
            sock = await self.make_socket(af, socket.SOCK_DGRAM, 0, addr)
            await client_connected_cb(sock)
        elif socktype == socket.SOCK_STREAM:
            async def handle_tcp(r, w):
                sock_tcp = _StreamSocket(af, r, w)
                await client_connected_cb(sock_tcp)
            hostname, port = addr
            server = await asyncio.start_server(
                handle_tcp,
                host=hostname,
                port=port,
                family=af,
            )
            await server.serve_forever()
        raise NotImplementedError(
            "unsupported socket " + f"type {socktype}"
        )  # pragma: no cover

    async def sleep(self, interval):
        await asyncio.sleep(interval)

    def datagram_connection_required(self):
        return False

    def get_transport_class(self):
        return _HTTPTransport

    async def wait_for(self, awaitable, timeout):
        return await _maybe_wait_for(awaitable, timeout)
