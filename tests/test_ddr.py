# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import types

import pytest

import dns._ddr
import dns.asyncbackend
import dns.asyncresolver
import dns.nameserver
import dns.resolver
import dns.rrset
import tests.util


def _svcb_nameserver_kinds(svcb_text):
    rrset = dns.rrset.from_text("_dns.resolver.arpa.", 7200, "IN", "SVCB", svcb_text)
    answer = types.SimpleNamespace(nameserver="192.0.2.1", rrset=rrset)
    infos = dns._ddr._extract_nameservers_from_svcb(answer)
    return [ns.kind() for info in infos for ns in info.nameservers]


def test_svcb_dot_kept_when_h2_has_no_dohpath():
    # A record advertising both dot and h2 but no (valid) dohpath must still
    # yield the dot designated resolver; the missing dohpath only rules out
    # the DoH nameserver.
    kinds = _svcb_nameserver_kinds('1 dot1.example.net. alpn="dot,h2" port=8530')
    assert kinds == ["DoT"]
    kinds = _svcb_nameserver_kinds('1 dot1.example.net. alpn="h2,dot" port=8530')
    assert kinds == ["DoT"]


def test_svcb_all_transports_extracted():
    kinds = _svcb_nameserver_kinds(
        '1 r.example.net. alpn="dot,h2,doq" dohpath="/dns-query{?dns}"'
    )
    assert set(kinds) == {"DoH", "DoT", "DoQ"}


@pytest.mark.skipif(
    not tests.util.is_internet_reachable(), reason="Internet not reachable"
)
@tests.util.retry_on_timeout
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
@tests.util.retry_on_timeout
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
