# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import sys

import pytest

import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.query
import dns.rcode

from .util import have_ipv4, have_ipv6, here

try:
    from .nanoquic import Server

    _nanoquic_available = True
except ImportError:
    _nanoquic_available = False

    class Server(object):
        pass


addresses = []
if have_ipv4():
    addresses.append("127.0.0.1")
if have_ipv6():
    addresses.append("::1")
if len(addresses) == 0:
    # no networking
    _nanoquic_available = False


@pytest.mark.skipif(not _nanoquic_available, reason="requires aioquic")
def test_basic_sync():
    q = dns.message.make_query("www.example.", "A")
    for address in addresses:
        with Server(address) as server:
            r = dns.query.quic(q, address, port=server.port, verify=here("tls/ca.crt"))
            assert r.rcode() == dns.rcode.REFUSED


async def amain(address, port):
    q = dns.message.make_query("www.example.", "A")
    r = await dns.asyncquery.quic(q, address, port=port, verify=here("tls/ca.crt"))
    assert r.rcode() == dns.rcode.REFUSED


@pytest.mark.skipif(not _nanoquic_available, reason="requires aioquic")
def test_basic_asyncio():
    dns.asyncbackend.set_default_backend("asyncio")
    for address in addresses:
        with Server(address) as server:
            asyncio.run(amain(address, server.port))


try:
    import trio

    @pytest.mark.skipif(not _nanoquic_available, reason="requires aioquic")
    def test_basic_trio():
        dns.asyncbackend.set_default_backend("trio")
        for address in addresses:
            with Server(address) as server:
                trio.run(amain, address, server.port)

except ImportError:
    pass
