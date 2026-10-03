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


def _ddr_check_certificate(bootstrap_address, san_ip):
    info = dns._ddr._SVCBInfo(bootstrap_address, 853, "dns.example", [])
    cert = {"subjectAltName": (("DNS", "dns.example"), ("IP Address", san_ip))}
    return info.ddr_check_certificate(cert)


def test_ddr_check_certificate_ipv6():
    # ssl.SSLSocket.getpeercert() renders IPv6 SAN entries uncompressed and in
    # upper case, so the check must compare addresses, not text.
    assert _ddr_check_certificate("2001:4860:4860::8888", "2001:4860:4860:0:0:0:0:8888")
    assert _ddr_check_certificate("2620:fe::fe", "2620:FE:0:0:0:0:0:FE")
    assert _ddr_check_certificate("::1", "0:0:0:0:0:0:0:1")
    assert not _ddr_check_certificate(
        "2001:4860:4860::8844", "2001:4860:4860:0:0:0:0:8888"
    )


def test_ddr_check_certificate_ipv4():
    assert _ddr_check_certificate("8.8.8.8", "8.8.8.8")
    assert not _ddr_check_certificate("8.8.8.8", "8.8.4.4")
    # A SAN entry of the other family is skipped, not an error.
    assert not _ddr_check_certificate("8.8.8.8", "0:0:0:0:0:FFFF:808:808")
    assert not _ddr_check_certificate("2001:4860:4860::8888", "8.8.8.8")


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
