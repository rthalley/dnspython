# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pytest

import dns.exception
import dns.name
import dns.reversename


@pytest.mark.parametrize("origin", ["ip6.arpa.", "custom.example."])
@pytest.mark.parametrize(
    "labels",
    [
        ["0"] * 29,
        ["0"] * 30,
        ["0"] * 31,
        ["0"] * 33,
        ["00"] + ["0"] * 30,
        ["00"] + ["0"] * 31,
        ["g"] + ["0"] * 31,
    ],
    ids=[
        "29-labels",
        "30-labels",
        "31-labels",
        "33-labels",
        "wide-label",
        "32-wide-label",
        "non-hex",
    ],
)
def test_invalid_ipv6_reverse_name(labels, origin):
    v6_origin = dns.name.from_text(origin)
    name = dns.name.from_text(".".join(labels), origin=v6_origin)

    with pytest.raises(dns.exception.SyntaxError):
        dns.reversename.to_address(name, v6_origin=v6_origin)


@pytest.mark.parametrize("origin", ["ip6.arpa.", "custom.example."])
@pytest.mark.parametrize(
    "address", ["::", "::1", "2001:db8::1", "4321:0:1:2:3:4:567:89ab"]
)
def test_ipv6_reverse_name_roundtrip(address, origin):
    v6_origin = dns.name.from_text(origin)
    name = dns.reversename.from_address(address, v6_origin=v6_origin)

    assert dns.reversename.to_address(name, v6_origin=v6_origin) == address
    assert (
        dns.reversename.to_address(
            dns.name.from_text(name.to_text().upper()), v6_origin=v6_origin
        )
        == address
    )


@pytest.mark.parametrize("origin", ["in-addr.arpa.", "custom.example."])
@pytest.mark.parametrize(
    "text",
    [
        r"4\.3\.2\.1",
        r"2\.1.3.4",
        r"1.2\.3.4",
        r"4.3.2\.1",
        "3.2.1",
        "5.4.3.2.1",
    ],
    ids=[
        "one-label",
        "escaped-dot-first",
        "escaped-dot-middle",
        "escaped-dot-last",
        "3-labels",
        "5-labels",
    ],
)
def test_invalid_ipv4_reverse_name(text, origin):
    v4_origin = dns.name.from_text(origin)
    name = dns.name.from_text(text, origin=v4_origin)

    with pytest.raises(dns.exception.SyntaxError):
        dns.reversename.to_address(name, v4_origin=v4_origin)


@pytest.mark.parametrize("origin", ["in-addr.arpa.", "custom.example."])
@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "192.0.2.255"])
def test_ipv4_reverse_name_roundtrip(address, origin):
    v4_origin = dns.name.from_text(origin)
    name = dns.reversename.from_address(address, v4_origin=v4_origin)

    assert dns.reversename.to_address(name, v4_origin=v4_origin) == address
