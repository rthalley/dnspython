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

import dns.enum
import dns.exception
import dns.immutable
import dns.rdtypes.dnskeybase  # lgtm[py/import-and-import-from]

# pylint: disable=unused-import
from dns.rdtypes.dnskeybase import (  # noqa: F401  lgtm[py/unused-import]
    ZONE,
)

# pylint: enable=unused-import


class Protocol(dns.enum.IntEnum):
    NONE = 0
    TLS = 1
    EMAIL = 2
    DNSSEC = 3
    IPSEC = 4
    ALL = 255

    @classmethod
    def _maximum(cls):
        return 255


class LegacyFlag(dns.enum.IntEnum):
    NOCONF = 0x4000
    NOAUTH = 0x8000
    NOKEY = 0xC000
    FLAG2 = 0x2000
    EXTEND = 0x1000
    FLAG4 = 0x0800
    FLAG5 = 0x0400
    USER = 0x0000
    ZONE = 0x0100
    HOST = 0x0200
    NTYP3 = 0x0300
    FLAG8 = 0x0080
    FLAG9 = 0x0040
    FLAG10 = 0x0020
    FLAG11 = 0x0010
    SIG0 = 0x0000
    SIG1 = 0x0001
    SIG2 = 0x0002
    SIG3 = 0x0003
    SIG4 = 0x0004
    SIG5 = 0x0005
    SIG6 = 0x0006
    SIG7 = 0x0007
    SIG8 = 0x0008
    SIG9 = 0x0009
    SIG10 = 0x000A
    SIG11 = 0x000B
    SIG12 = 0x000C
    SIG13 = 0x000D
    SIG14 = 0x000E
    SIG15 = 0x000F


@dns.immutable.immutable
class KEY(dns.rdtypes.dnskeybase.DNSKEYBase):
    """KEY record"""

    @classmethod
    def from_text(
        cls, rdclass, rdtype, tok, origin=None, relativize=True, relativize_to=None
    ):
        try:
            flags = tok.get_uint16()
        except dns.exception.SyntaxError:
            tok.unget(tok.last_token)
            flags_str = tok.get().value
            try:
                flags = 0
                for mnemonic in flags_str.split("|"):
                    flags |= LegacyFlag[mnemonic].value
            except KeyError:
                raise dns.exception.SyntaxError(f"Invalid flags: {flags_str}")

        try:
            protocol = tok.get_uint8()
        except dns.exception.SyntaxError:
            tok.unget(tok.last_token)
            protocol_str = tok.get_string()
            try:
                protocol = Protocol[protocol_str].value
            except KeyError:
                raise dns.exception.SyntaxError(f"Invalid protocol: {protocol_str}")

        algorithm = tok.get_string()

        # RFC 2535 section 7.1 says "Note that if the type flags field has the
        # NOKEY value, nothing appears after the algorithm octet."
        if flags != LegacyFlag.NOKEY:
            b64 = tok.concatenate_remaining_identifiers().encode()
            key = base64.b64decode(b64)
        else:
            key = b""

        return cls(rdclass, rdtype, flags, protocol, algorithm, key)
