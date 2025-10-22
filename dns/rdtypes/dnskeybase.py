# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2004-2007, 2009-2011 Nominum, Inc.
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

import base64
import enum
import struct
from typing import TypeVar

import dns.dnssectypes
import dns.exception
import dns.immutable
import dns.rdata

# wildcard import
__all__ = ["SEP", "REVOKE", "ZONE"]  # noqa: F822


class Flag(enum.IntFlag):
    SEP = 0x0001
    ADT = 0x0002
    REVOKE = 0x0080
    ZONE = 0x0100


T = TypeVar("T", bound="DNSKEYBase")


@dns.immutable.immutable
class DNSKEYBase(dns.rdata.Rdata):
    """Base class for rdata that is like a DNSKEY record"""

    __slots__ = ["flags", "protocol", "algorithm", "key"]

    def __init__(self, rdclass, rdtype, flags, protocol, algorithm, key):
        super().__init__(rdclass, rdtype)
        self.flags: int = Flag(self._as_uint16(flags))
        self.protocol: int = self._as_uint8(protocol)
        self.algorithm: dns.dnssectypes.Algorithm = dns.dnssectypes.Algorithm.make(
            algorithm
        )
        self.key: bytes = self._as_bytes(key)

    def to_styled_text(self, style: dns.rdata.RdataStyle) -> str:
        if style.truncate_crypto:
            key = f"[key id = {self.key_id()}]"
        else:
            key = dns.rdata._styled_base64ify(self.key, style)
        return f"{self.flags} {self.protocol} {self.algorithm} {key}"

    @classmethod
    def from_text(
        cls: type[T],
        rdclass,
        rdtype,
        tok,
        origin=None,
        relativize=True,
        relativize_to=None,
    ) -> T:
        flags = tok.get_uint16()
        protocol = tok.get_uint8()
        algorithm = tok.get_string()
        b64 = tok.concatenate_remaining_identifiers().encode()
        key = base64.b64decode(b64)
        return cls(rdclass, rdtype, flags, protocol, algorithm, key)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        header = struct.pack("!HBB", self.flags, self.protocol, self.algorithm)
        file.write(header)
        file.write(self.key)

    @classmethod
    def from_wire_parser(cls: type[T], rdclass, rdtype, parser, origin=None) -> T:
        header = parser.get_struct("!HBB")
        key = parser.get_remaining()
        return cls(rdclass, rdtype, header[0], header[1], header[2], key)

    def key_id(self) -> int:
        """Return the key id (a 16-bit number) for the specified key.

        *key*, a ``dns.rdtypes.ANY.DNSKEY.DNSKEY``

        Returns an ``int`` between 0 and 65535
        """

        wire = self.to_wire()
        assert wire is not None  # for mypy
        if self.algorithm == dns.dnssectypes.Algorithm.RSAMD5:
            return (wire[-3] << 8) + wire[-2]
        else:
            total = 0
            for i in range(len(wire) // 2):
                total += (wire[2 * i] << 8) + wire[2 * i + 1]
            if len(wire) % 2 != 0:
                total += wire[len(wire) - 1] << 8
            total += (total >> 16) & 0xFFFF
            return total & 0xFFFF
            return total & 0xFFFF


### BEGIN generated Flag constants

SEP = Flag.SEP
ADT = Flag.ADT
REVOKE = Flag.REVOKE
ZONE = Flag.ZONE

### END generated Flag constants
