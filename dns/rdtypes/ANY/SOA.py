# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
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
import dns.rdata
import dns.name


class SOA(dns.rdata.Rdata):

    """SOA record"""

    # see: RFC 1035

    __slots__ = ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire',
                 'minimum']

    def __init__(self, rdclass, rdtype, mname, rname, serial, refresh, retry,
                 expire, minimum):
        super().__init__(rdclass, rdtype)
        object.__setattr__(self, 'mname', mname)
        object.__setattr__(self, 'rname', rname)
        object.__setattr__(self, 'serial', serial)
        object.__setattr__(self, 'refresh', refresh)
        object.__setattr__(self, 'retry', retry)
        object.__setattr__(self, 'expire', expire)
        object.__setattr__(self, 'minimum', minimum)

    def to_text(self, origin=None, relativize=True, **kw):
        mname = self.mname.choose_relativity(origin, relativize)
        rname = self.rname.choose_relativity(origin, relativize)
        return '%s %s %d %d %d %d %d' % (
            mname, rname, self.serial, self.refresh, self.retry,
            self.expire, self.minimum)

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True,
                  relativize_to=None):
        mname = tok.get_name(origin, relativize, relativize_to)
        rname = tok.get_name(origin, relativize, relativize_to)
        serial = tok.get_uint32()
        refresh = tok.get_ttl()
        retry = tok.get_ttl()
        expire = tok.get_ttl()
        minimum = tok.get_ttl()
        tok.get_eol()
        return cls(rdclass, rdtype, mname, rname, serial, refresh, retry,
                   expire, minimum)

    def to_wire(self, file, compress=None, origin=None):
        self.mname.to_wire(file, compress, origin)
        self.rname.to_wire(file, compress, origin)
        five_ints = struct.pack('!IIIII', self.serial, self.refresh,
                                self.retry, self.expire, self.minimum)
        file.write(five_ints)

    def to_digestable(self, origin=None):
        return self.mname.to_digestable(origin) + \
            self.rname.to_digestable(origin) + \
            struct.pack('!IIIII', self.serial, self.refresh,
                        self.retry, self.expire, self.minimum)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        (mname, cused) = dns.name.from_wire(wire[: current + rdlen], current)
        current += cused
        rdlen -= cused
        (rname, cused) = dns.name.from_wire(wire[: current + rdlen], current)
        current += cused
        rdlen -= cused
        if rdlen != 20:
            raise dns.exception.FormError
        five_ints = struct.unpack('!IIIII',
                                  wire[current: current + rdlen])
        if origin is not None:
            mname = mname.relativize(origin)
            rname = rname.relativize(origin)
        return cls(rdclass, rdtype, mname, rname,
                   five_ints[0], five_ints[1], five_ints[2], five_ints[3],
                   five_ints[4])
