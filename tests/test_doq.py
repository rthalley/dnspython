# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import sys

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
    from .nanonameserver import Server
except ImportError:
    pass

if not have_quic:

    class Server(object):
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
