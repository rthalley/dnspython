# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import sys

import pytest

import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.query
import dns.rcode

from .util import here

try:
    from .nanoquic import Server

    _nanoquic_available = True
except ImportError:
    _nanoquic_available = False

    class Server(object):
        pass


@pytest.mark.skipif(not _nanoquic_available, reason="requires nanoquic")
def test_basic_sync():
    with Server() as server:
        q = dns.message.make_query("www.example.", "A")
        r = dns.query.quic(q, "127.0.0.1", port=8853, verify=here("tls/ca.crt"))
        assert r.rcode() == dns.rcode.REFUSED


async def amain():
    q = dns.message.make_query("www.example.", "A")
    r = await dns.asyncquery.quic(q, "127.0.0.1", port=8853, verify=here("tls/ca.crt"))
    assert r.rcode() == dns.rcode.REFUSED


@pytest.mark.skipif(not _nanoquic_available, reason="requires nanoquic")
def test_basic_asyncio():
    dns.asyncbackend.set_default_backend("asyncio")
    with Server() as server:
        asyncio.run(amain())


try:
    import trio

    @pytest.mark.skipif(not _nanoquic_available, reason="requires nanoquic")
    def test_basic_trio():
        dns.asyncbackend.set_default_backend("trio")
        with Server() as server:
            trio.run(amain)

except ImportError:
    pass
