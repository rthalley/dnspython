# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2001-2017 Nominum, Inc.
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

"""DNS Message Flags."""

import enum
from typing import Any

# Standard DNS flags


class Flag(enum.IntFlag):
    #: Query Response
    QR = 0x8000
    #: Authoritative Answer
    AA = 0x0400
    #: Truncated Response
    TC = 0x0200
    #: Recursion Desired
    RD = 0x0100
    #: Recursion Available
    RA = 0x0080
    #: Authentic Data
    AD = 0x0020
    #: Checking Disabled
    CD = 0x0010


# EDNS flags


class EDNSFlag(enum.IntFlag):
    #: DNSSEC answer OK
    DO = 0x8000
    #: Compact nonexistence, restore NXDOMAIN requested
    CO = 0x4000
    #: DELEG aware
    DE = 0x2000


# Flags Mask (excludes opcode and rcode)
FLAGS_MASK = 0x87F0

# EDNS Flags Mask (excludes extended rcode and version)
EDNS_FLAGS_MASK = 0x0000FFFF


def _from_text(text: str, enum_class: Any) -> int:
    flags = 0
    tokens = text.split()
    for t in tokens:
        token = t.upper()
        if token.startswith("FLAG") and token[4:].isdigit():
            # An unnamed flag, rendered by _to_text() as FLAGn (see below).
            flags |= 1 << int(token[4:])
        else:
            flags |= enum_class[token]
    return flags


def _to_text(flags: int, enum_class: Any) -> str:
    text_flags = []
    known = 0
    for k, v in enum_class.__members__.items():
        known |= int(v)
        if flags & v != 0:
            text_flags.append(k)
    # Render any set bits that do not have a named flag as FLAGn, where n is
    # the bit position, so that they are not silently dropped. These tokens
    # round-trip through _from_text().
    unknown = flags & ~known
    bit = 0
    while unknown:
        if unknown & 1:
            text_flags.append(f"FLAG{bit}")
        unknown >>= 1
        bit += 1
    return " ".join(text_flags)


def from_text(text: str) -> int:
    """Convert a space-separated list of flag text values into a flags
    value.

    :rtype: int
    """

    return _from_text(text, Flag)


def to_text(flags: int) -> str:
    """Convert a flags value into a space-separated list of flag text
    values.

    :rtype: str
    """

    # We & with 0xff0 to mask out rcode.
    return _to_text(flags & FLAGS_MASK, Flag)


def edns_from_text(text: str) -> int:
    """Convert a space-separated list of EDNS flag text values into a EDNS
    flags value.

    :rtype: int
    """

    return _from_text(text, EDNSFlag)


def edns_to_text(flags: int) -> str:
    """Convert an EDNS flags value into a space-separated list of EDNS flag
    text values.

    :rtype: str
    """

    return _to_text(flags & EDNS_FLAGS_MASK, EDNSFlag)


### BEGIN generated Flag constants

QR = Flag.QR
AA = Flag.AA
TC = Flag.TC
RD = Flag.RD
RA = Flag.RA
AD = Flag.AD
CD = Flag.CD

### END generated Flag constants

### BEGIN generated EDNSFlag constants

DO = EDNSFlag.DO
CO = EDNSFlag.CO
DE = EDNSFlag.DE

### END generated EDNSFlag constants
