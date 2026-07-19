# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import struct

import dns.immutable
import dns.name
import dns.rdata


@dns.immutable.immutable
class LP(dns.rdata.Rdata):
    """LP record"""

    # see: rfc6742.txt

    __slots__ = ["preference", "fqdn"]

    def __init__(self, rdclass, rdtype, preference, fqdn):
        super().__init__(rdclass, rdtype)
        self.preference: int = self._as_uint16(preference)
        self.fqdn: dns.name.Name = self._as_name(fqdn)

    def to_styled_text(self, style: dns.rdata.RdataStyle) -> str:
        return f"{self.preference} {self.fqdn.to_styled_text(style)}"

    @classmethod
    def from_text(
        cls, rdclass, rdtype, tok, origin=None, relativize=True, relativize_to=None
    ):
        preference = tok.get_uint16()
        fqdn = tok.get_name(origin, relativize, relativize_to)
        return cls(rdclass, rdtype, preference, fqdn)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        file.write(struct.pack("!H", self.preference))
        # LP is not an RFC 1035 type, so per RFC 3597 section 4 its FQDN is
        # never compressed, and per RFC 4034 section 6.2 (as amended by RFC
        # 6840 section 5.1) it is not downcased for the canonical form.
        self.fqdn.to_wire(file, None, origin, False)

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None):
        preference = parser.get_uint16()
        fqdn = parser.get_name(origin)
        return cls(rdclass, rdtype, preference, fqdn)
