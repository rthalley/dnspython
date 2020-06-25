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

import struct

import dns.edns
import dns.exception
import dns.rdata


class OPT(dns.rdata.Rdata):

    """OPT record"""

    __slots__ = ['options']

    def __init__(self, rdclass, rdtype, options):
        """Initialize an OPT rdata.

        *rdclass*, an ``int`` is the rdataclass of the Rdata,
        which is also the payload size.

        *rdtype*, an ``int`` is the rdatatype of the Rdata.

        *options*, a tuple of ``bytes``
        """

        super().__init__(rdclass, rdtype)
        object.__setattr__(self, 'options', dns.rdata._constify(options))

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        for opt in self.options:
            owire = opt.to_wire()
            file.write(struct.pack("!HH", opt.otype, len(owire)))
            file.write(owire)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        options = []
        while rdlen > 0:
            if rdlen < 4:
                raise dns.exception.FormError
            (otype, olen) = struct.unpack('!HH', wire[current:current + 4])
            current += 4
            rdlen -= 4
            if olen > rdlen:
                raise dns.exception.FormError
            opt = dns.edns.option_from_wire(otype, wire, current, olen)
            current += olen
            rdlen -= olen
            options.append(opt)
        return cls(rdclass, rdtype, options)

    @property
    def payload(self):
        "payload size"
        return self.rdclass
