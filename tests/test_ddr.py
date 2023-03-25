# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import time

import pytest

import dns.asyncbackend
import dns.asyncresolver
import dns.resolver
import dns.nameserver

import tests.util


@pytest.mark.skipif(
    not tests.util.is_internet_reachable(), reason="Internet not reachable"
)
def test_basic_ddr_sync():
    for nameserver in ["1.1.1.1", "8.8.8.8"]:
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = [nameserver]
        res.try_ddr()
        for nameserver in res.nameservers:
            assert isinstance(nameserver, dns.nameserver.Nameserver)
            assert nameserver.kind() != "Do53"


@pytest.mark.skipif(
    not tests.util.is_internet_reachable(), reason="Internet not reachable"
)
def test_basic_ddr_async():
    async def run():
        dns.asyncbackend._default_backend = None
        for nameserver in ["1.1.1.1", "8.8.8.8"]:
            res = dns.asyncresolver.Resolver(configure=False)
            res.nameservers = [nameserver]
            await res.try_ddr()
            for nameserver in res.nameservers:
                assert isinstance(nameserver, dns.nameserver.Nameserver)
                assert nameserver.kind() != "Do53"

    asyncio.run(run())
