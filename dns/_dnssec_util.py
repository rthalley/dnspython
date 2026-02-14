# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
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

"""Shared DNSSEC utility functions"""

from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.CDNSKEY import CDNSKEY
from dns.rdtypes.ANY.DNSKEY import DNSKEY


def key_id(key: DNSKEY | CDNSKEY) -> int:
    """Return the key id (a 16-bit number) for the specified key.

    *key*, a ``dns.rdtypes.ANY.DNSKEY.DNSKEY``

    Returns an ``int`` between 0 and 65535
    """

    rdata = key.to_wire()
    assert rdata is not None  # for mypy
    if key.algorithm == Algorithm.RSAMD5:
        return (rdata[-3] << 8) + rdata[-2]
    else:
        total = 0
        for i in range(len(rdata) // 2):
            total += (rdata[2 * i] << 8) + rdata[2 * i + 1]
        if len(rdata) % 2 != 0:
            total += rdata[len(rdata) - 1] << 8
        total += (total >> 16) & 0xFFFF
        return total & 0xFFFF
        return total & 0xFFFF
