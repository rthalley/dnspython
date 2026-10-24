# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2005-2007, 2009-2011 Nominum, Inc.
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

import binascii
import struct
from typing import TypeVar

import dns.immutable
import dns.rdata
import dns.rdatatype

T = TypeVar("T", bound="TLSABase")


@dns.immutable.immutable
class TLSABase(dns.rdata.Rdata):
    """Base class for TLSA and SMIMEA records"""

    # see: RFC 6698

    __slots__ = ["usage", "selector", "mtype", "cert"]

    # Matching type registry (RFC 6698 Section 2.1.3): type 1 is SHA-256 and
    # type 2 is SHA-512.  Type 0 stores a full certificate and has no fixed
    # length.
    _cert_length_by_mtype = {
        1: 32,  # SHA-256, RFC 6698 Section 2.1.3
        2: 64,  # SHA-512, RFC 6698 Section 2.1.3
    }

    def __init__(self, rdclass, rdtype, usage, selector, mtype, cert):
        super().__init__(rdclass, rdtype)
        self.usage: int = self._as_uint8(usage)
        self.selector: int = self._as_uint8(selector)
        self.mtype: int = self._as_uint8(mtype)
        self.cert: bytes = self._as_bytes(cert)
        expected = self._cert_length_by_mtype.get(self.mtype)
        if expected is not None and len(self.cert) != expected:
            raise ValueError(
                "certificate association data length inconsistent with matching type"
            )

    def to_styled_text(self, style: dns.rdata.RdataStyle) -> str:
        cert = dns.rdata._styled_hexify(self.cert, style, True)
        return f"{self.usage} {self.selector} {self.mtype} {cert}"

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
        usage = tok.get_uint8()
        selector = tok.get_uint8()
        mtype = tok.get_uint8()
        cert = tok.concatenate_remaining_identifiers().encode()
        cert = binascii.unhexlify(cert)
        return cls(rdclass, rdtype, usage, selector, mtype, cert)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        header = struct.pack("!BBB", self.usage, self.selector, self.mtype)
        file.write(header)
        file.write(self.cert)

    @classmethod
    def from_wire_parser(cls: type[T], rdclass, rdtype, parser, origin=None) -> T:
        header = parser.get_struct("BBB")
        cert = parser.get_remaining()
        return cls(rdclass, rdtype, header[0], header[1], header[2], cert)
