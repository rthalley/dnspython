import pytest

import dns.name
from dns.rdtypes.util import Gateway


@pytest.mark.parametrize("relative", [False, True])
def test_gateway_name_text_honors_relativize(relative):
    origin = dns.name.from_text("example.")
    gateway = Gateway(3, dns.name.from_text("gateway.example."))
    expected = "gateway" if relative else "gateway.example."
    assert gateway.to_text(origin=origin, relativize=relative) == expected


@pytest.mark.parametrize("relative", [False, True])
def test_gateway_name_at_origin(relative):
    origin = dns.name.from_text("example.")
    gateway = Gateway(3, origin)
    assert gateway.to_text(origin=origin, relativize=relative) == (
        "@" if relative else "example."
    )


def test_gateway_without_origin_keeps_absolute_name():
    gateway = Gateway(3, dns.name.from_text("gateway.example."))
    assert gateway.to_text(relativize=False) == "gateway.example."


@pytest.mark.parametrize(
    "kind, value", [(0, None), (1, "192.0.2.1"), (2, "2001:db8::1")]
)
def test_other_gateway_types_ignore_name_style(kind, value):
    gateway = Gateway(kind, value)
    expected = "." if value is None else value
    assert (
        gateway.to_text(origin=dns.name.from_text("example."), relativize=False)
        == expected
    )
