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
