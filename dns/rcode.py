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

"""DNS Result Codes."""

import enum

import dns.exception

class Rcode(enum.IntEnum):
    #: No error
    NOERROR = 0
    #: Format error
    FORMERR = 1
    #: Server failure
    SERVFAIL = 2
    #: Name does not exist ("Name Error" in RFC 1025 terminology).
    NXDOMAIN = 3
    #: Not implemented
    NOTIMP = 4
    #: Refused
    REFUSED = 5
    #: Name exists.
    YXDOMAIN = 6
    #: RRset exists.
    YXRRSET = 7
    #: RRset does not exist.
    NXRRSET = 8
    #: Not authoritative.
    NOTAUTH = 9
    #: Name not in zone.
    NOTZONE = 10
    #: Bad EDNS version.
    BADVERS = 16

globals().update(Rcode.__members__)

class UnknownRcode(dns.exception.DNSException):
    """A DNS rcode is unknown."""


def from_text(text):
    """Convert text into an rcode.

    *text*, a ``str``, the textual rcode or an integer in textual form.

    Raises ``dns.rcode.UnknownRcode`` if the rcode mnemonic is unknown.

    Returns an ``int``.
    """

    if text.isdigit():
        v = int(text)
        if v >= 0 and v <= 4095:
            try:
                return Rcode(v)
            except ValueError:
                return v
    try:
        return Rcode[text.upper()]
    except KeyError:
        raise UnknownRcode


def from_flags(flags, ednsflags):
    """Return the rcode value encoded by flags and ednsflags.

    *flags*, an ``int``, the DNS flags field.

    *ednsflags*, an ``int``, the EDNS flags field.

    Raises ``ValueError`` if rcode is < 0 or > 4095

    Returns an ``int``.
    """

    value = (flags & 0x000f) | ((ednsflags >> 20) & 0xff0)
    if value < 0 or value > 4095:
        raise ValueError('rcode must be >= 0 and <= 4095')
    return value


def to_flags(value):
    """Return a (flags, ednsflags) tuple which encodes the rcode.

    *value*, an ``int``, the rcode.

    Raises ``ValueError`` if rcode is < 0 or > 4095.

    Returns an ``(int, int)`` tuple.
    """

    if value < 0 or value > 4095:
        raise ValueError('rcode must be >= 0 and <= 4095')
    v = value & 0xf
    ev = (value & 0xff0) << 20
    return (v, ev)


def to_text(value):
    """Convert rcode into text.

    *value*, and ``int``, the rcode.

    Raises ``ValueError`` if rcode is < 0 or > 4095.

    Returns a ``str``.
    """

    if value < 0 or value > 4095:
        raise ValueError('rcode must be >= 0 and <= 4095')
    try:
        return Rcode(value).name
    except ValueError:
        return str(value)
