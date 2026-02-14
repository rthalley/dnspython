# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2006, 2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import struct

import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdtypes.util


class Relay(dns.rdtypes.util.Gateway):
    name = "AMTRELAY relay"

    @property
    def relay(self) -> str | dns.name.Name | None:
        return self.gateway


@dns.immutable.immutable
class AMTRELAY(dns.rdata.Rdata):
    """AMTRELAY record"""

    # see: RFC 8777

    __slots__ = ["precedence", "discovery_optional", "relay_type", "relay"]

    def __init__(
        self, rdclass, rdtype, precedence, discovery_optional, relay_type, relay
    ):
        super().__init__(rdclass, rdtype)
        relay = Relay(relay_type, relay)
        self.precedence: int = self._as_uint8(precedence)
        self.discovery_optional: bool = self._as_bool(discovery_optional)
        self.relay_type: int = relay.type
        self.relay: str | dns.name.Name | None = relay.relay

    def to_styled_text(self, style: dns.rdata.RdataStyle) -> str:
        relay = Relay(self.relay_type, self.relay).to_styled_text(style)
        return (
            f"{self.precedence} {self.discovery_optional:d} {self.relay_type} {relay}"
        )

    @classmethod
    def from_text(
        cls, rdclass, rdtype, tok, origin=None, relativize=True, relativize_to=None
    ) -> "AMTRELAY":
        precedence = tok.get_uint8()
        discovery_optional = tok.get_uint8()
        if discovery_optional > 1:
            raise dns.exception.SyntaxError("expecting 0 or 1")
        discovery_optional = bool(discovery_optional)
        relay_type = tok.get_uint8()
        if relay_type > 0x7F:
            raise dns.exception.SyntaxError("expecting an integer <= 127")
        relay = Relay.from_text(relay_type, tok, origin, relativize, relativize_to)
        return cls(
            rdclass, rdtype, precedence, discovery_optional, relay_type, relay.relay
        )

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        relay_type = self.relay_type | (self.discovery_optional << 7)
        header = struct.pack("!BB", self.precedence, relay_type)
        file.write(header)
        Relay(self.relay_type, self.relay).to_wire(file, compress, origin, canonicalize)

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None) -> "AMTRELAY":
        precedence, relay_type = parser.get_struct("!BB")
        discovery_optional = bool(relay_type >> 7)
        relay_type &= 0x7F
        relay = Relay.from_wire_parser(relay_type, parser, origin)
        return cls(
            rdclass, rdtype, precedence, discovery_optional, relay_type, relay.relay
        )
