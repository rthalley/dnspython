# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Address-like base classes."""

from typing import Any, Self

import dns.immutable
import dns.rdata


@dns.immutable.immutable
class AddressBase(dns.rdata.Rdata):
    """Base class for rdata whose only field is an IP address, like A and AAAA.

    Subclasses must implement ``_as_address()`` and ``_address_to_wire()``.
    """

    __slots__ = ["address"]

    def __init__(self, rdclass, rdtype, address):
        super().__init__(rdclass, rdtype)
        self.address: str = self._as_address(address)

    @classmethod
    def _as_address(cls, value: Any) -> str:
        raise NotImplementedError  # pragma: no cover

    @classmethod
    def _address_to_wire(cls, address: str) -> bytes:
        raise NotImplementedError  # pragma: no cover

    def to_styled_text(self, style: dns.rdata.RdataStyle) -> str:
        return self.address

    @classmethod
    def from_text(
        cls: type[Self],
        rdclass,
        rdtype,
        tok,
        origin=None,
        relativize=True,
        relativize_to=None,
    ) -> Self:
        address = tok.get_identifier()
        return cls(rdclass, rdtype, address)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        file.write(self._address_to_wire(self.address))

    @classmethod
    def from_wire_parser(cls: type[Self], rdclass, rdtype, parser, origin=None) -> Self:
        address = parser.get_remaining()
        return cls(rdclass, rdtype, address)
