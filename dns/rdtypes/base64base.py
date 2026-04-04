# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2016 Nominum, Inc.
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

import dns.exception
import dns.immutable
import dns.rdata
import dns.tokenizer


@dns.immutable.immutable
class Base64Base(dns.rdata.Rdata):
    """Base type for an rdata whose value is a single base64-encoded bytes."""

    def __init__(self, rdclass, rdtype, value):
        super().__init__(rdclass, rdtype)
        self.value = self._as_bytes(value)

    def to_styled_text(self, style: dns.rdata.RdataStyle) -> str:
        # Fixed style
        style = style.replace(base64_chunk_size=0)
        return dns.rdata._styled_base64ify(self.value, style, True)

    @classmethod
    def from_text(
        cls, rdclass, rdtype, tok, origin=None, relativize=True, relativize_to=None
    ):
        b64 = tok.concatenate_remaining_identifiers().encode()
        value = base64.b64decode(b64)
        return cls(rdclass, rdtype, value)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        file.write(self.value)

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None):
        value = parser.get_remaining()
        return cls(rdclass, rdtype, value)
