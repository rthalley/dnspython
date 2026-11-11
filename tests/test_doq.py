# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import sys
import unittest.mock

import pytest

import dns._features
import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.query
import dns.rcode

from .util import have_ipv4, have_ipv6, here

have_quic = dns._features.have("doq")
try:
    from dns.quic._common import UnexpectedEOF

    from .nanonameserver import Server
except ImportError:
    pass

if not have_quic:

    class Server(object):
        pass

    class UnexpectedEOF(Exception):
        pass


addresses = []
if have_ipv4():
    addresses.append("127.0.0.1")
if have_ipv6():
    addresses.append("::1")
if len(addresses) == 0:
    # no networking
    have_quic = False


@pytest.mark.skipif(not have_quic, reason="requires aioquic")
def test_basic_sync():
    q = dns.message.make_query("www.example.", "A")
    for address in addresses:
        with Server(address=address) as server:
            port = server.doq_address[1]
            r = dns.query.quic(q, address, port=port, verify=here("tls/ca.crt"))
            assert r.rcode() == dns.rcode.REFUSED


async def amain(address, port):
    q = dns.message.make_query("www.example.", "A")
    r = await dns.asyncquery.quic(q, address, port=port, verify=here("tls/ca.crt"))
    assert r.rcode() == dns.rcode.REFUSED


@pytest.mark.skipif(not have_quic, reason="requires aioquic")
def test_basic_asyncio():
    dns.asyncbackend.set_default_backend("asyncio")
    for address in addresses:
        with Server(address=address) as server:
            port = server.doq_address[1]
            asyncio.run(amain(address, port))


try:
    import trio

    @pytest.mark.skipif(not have_quic, reason="requires aioquic")
    def test_basic_trio():
        dns.asyncbackend.set_default_backend("trio")
        for address in addresses:
            with Server(address=address) as server:
                port = server.doq_address[1]
                trio.run(amain, address, port)

except ImportError:
    pass


@pytest.mark.skipif(not have_quic, reason="requires aioquic")
def test_hostname_sync():
    q = dns.message.make_query("www.example.", "A")
    for address in addresses:
        with Server(address=address) as server:
            port = server.doq_address[1]
            r = dns.query.quic(
                q, address, port=port, verify=here("tls/ca.crt"), hostname="localhost"
            )
            assert r.rcode() == dns.rcode.REFUSED
            with pytest.raises(UnexpectedEOF):
                dns.query.quic(
                    q,
                    address,
                    port=port,
                    verify=here("tls/ca.crt"),
                    hostname="wrong.example",
                )


async def ahostname(address, port):
    q = dns.message.make_query("www.example.", "A")
    r = await dns.asyncquery.quic(
        q, address, port=port, verify=here("tls/ca.crt"), hostname="localhost"
    )
    assert r.rcode() == dns.rcode.REFUSED
    rejected = False
    try:
        await dns.asyncquery.quic(
            q, address, port=port, verify=here("tls/ca.crt"), hostname="wrong.example"
        )
    except* UnexpectedEOF:
        # except* as trio wraps the error in an ExceptionGroup
        rejected = True
    assert rejected


@pytest.mark.skipif(not have_quic, reason="requires aioquic")
def test_hostname_asyncio():
    dns.asyncbackend.set_default_backend("asyncio")
    for address in addresses:
        with Server(address=address) as server:
            port = server.doq_address[1]
            asyncio.run(ahostname(address, port))


try:
    import trio

    @pytest.mark.skipif(not have_quic, reason="requires aioquic")
    def test_hostname_trio():
        dns.asyncbackend.set_default_backend("trio")
        for address in addresses:
            with Server(address=address) as server:
                port = server.doq_address[1]
                trio.run(ahostname, address, port)

except ImportError:
    pass


class H3Manager:
    def is_h3(self):
        return True


@pytest.mark.skipif(not dns._features.have("doq"), reason="requires aioquic")
@pytest.mark.parametrize("backend", ["Sync", "Asyncio", "Trio"])
def test_h3_stream_reset(backend):
    if backend == "Trio":
        trio = pytest.importorskip("trio")
    import importlib

    import aioquic.quic.configuration
    import aioquic.quic.connection
    from aioquic.quic.events import StreamReset

    module = importlib.import_module(f"dns.quic._{backend.lower()}")
    reset = StreamReset(error_code=0x10C, stream_id=0)

    def setup():
        quic = aioquic.quic.connection.QuicConnection(
            configuration=aioquic.quic.configuration.QuicConfiguration(
                alpn_protocols=["h3"], is_client=True
            )
        )
        connection = getattr(module, f"{backend}QuicConnection")(
            quic, "127.0.0.1", 853, None, 0, H3Manager()
        )
        connection._connection = unittest.mock.Mock(
            next_event=unittest.mock.Mock(side_effect=[reset, None])
        )
        connection._h3_conn = unittest.mock.Mock(wraps=connection._h3_conn)
        connection._streams[0] = getattr(module, f"{backend}QuicStream")(connection, 0)
        return connection

    def close(connection):
        for name in ("_socket", "_send_wakeup", "_receive_wakeup"):
            sock = getattr(connection, name, None)
            if sock is not None:
                sock.close()

    async def run():
        # trio requires its objects to be created and closed in its event loop.
        connection = setup()
        await connection._handle_events()
        close(connection)
        return connection

    if backend == "Sync":
        connection = setup()
        connection._handle_events()
        close(connection)
    elif backend == "Asyncio":
        connection = asyncio.run(run())
    else:
        connection = trio.run(run)

    # The reset reaches the H3 connection, and ends the stream.
    connection._h3_conn.handle_event.assert_called_once_with(reset)
    assert connection._streams[0]._buffer.seen_end()
