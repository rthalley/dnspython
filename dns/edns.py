# Copyright (C) 2009, 2011 Nominum, Inc.
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

"""EDNS Options"""

from __future__ import absolute_import

import math
import struct

import dns.inet


NSID = 3
ECS = 8


class Option(object):

    """Base class for all EDNS option types.
    """

    def __init__(self, otype):
        """Initialize an option.
        @param otype: The rdata type
        @type otype: int
        """
        self.otype = otype

    def to_wire(self, file):
        """Convert an option to wire format.
        """
        raise NotImplementedError

    @classmethod
    def from_wire(cls, otype, wire, current, olen):
        """Build an EDNS option object from wire format

        @param otype: The option type
        @type otype: int
        @param wire: The wire-format message
        @type wire: string
        @param current: The offset in wire of the beginning of the rdata.
        @type current: int
        @param olen: The length of the wire-format option data
        @type olen: int
        @rtype: dns.edns.Option instance"""
        raise NotImplementedError

    def _cmp(self, other):
        """Compare an EDNS option with another option of the same type.
        Return < 0 if self < other, 0 if self == other,
        and > 0 if self > other.
        """
        raise NotImplementedError

    def __eq__(self, other):
        if not isinstance(other, Option):
            return False
        if self.otype != other.otype:
            return False
        return self._cmp(other) == 0

    def __ne__(self, other):
        if not isinstance(other, Option):
            return False
        if self.otype != other.otype:
            return False
        return self._cmp(other) != 0

    def __lt__(self, other):
        if not isinstance(other, Option) or \
                self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) < 0

    def __le__(self, other):
        if not isinstance(other, Option) or \
                self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) <= 0

    def __ge__(self, other):
        if not isinstance(other, Option) or \
                self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) >= 0

    def __gt__(self, other):
        if not isinstance(other, Option) or \
                self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) > 0


class GenericOption(Option):

    """Generate Rdata Class

    This class is used for EDNS option types for which we have no better
    implementation.
    """

    def __init__(self, otype, data):
        super(GenericOption, self).__init__(otype)
        self.data = data

    def to_wire(self, file):
        file.write(self.data)

    def to_text(self):
        return "Generic %d" % self.otype

    @classmethod
    def from_wire(cls, otype, wire, current, olen):
        return cls(otype, wire[current: current + olen])

    def _cmp(self, other):
        if self.data == other.data:
            return 0
        if self.data > other.data:
            return 1
        return -1


class ECSOption(Option):
    """EDNS Client Subnet (ECS, RFC7871)"""

    def __init__(self, address, srclen=None, scopelen=0):
        """Generate an ECS option

        @ivar address: client address information
        @type address: string
        @ivar srclen: prefix length, leftmost number of bits of the address
        to be used for the lookup. Sent by client, mirrored by server in
        responses. If not provided at init, will use /24 for v4 and /56 for v6
        @type srclen: int
        @ivar scopelen: prefix length, leftmost number of bits of the address
        that the response covers. 0 in queries, set by server.
        @type scopelen: int
        """
        super(ECSOption, self).__init__(ECS)
        af = dns.inet.af_for_address(address)

        if af == dns.inet.AF_INET6:
            self.family = 2
            if srclen is None:
                srclen = 56
        elif af == dns.inet.AF_INET:
            self.family = 1
            if srclen is None:
                srclen = 24
        else:
            raise ValueError('Bad ip family')

        self.srclen = srclen
        self.scopelen = scopelen
        self.address = address

        addrdata = dns.inet.inet_pton(af, address)
        nbytes = int(math.ceil(srclen/8.0))

        # Truncate to srclen and pad to the end of the last octet needed
        # See RFC section 6
        self.addrdata = addrdata[:nbytes]
        nbits = srclen % 8
        if nbits != 0:
            last = struct.pack('B', ord(self.addrdata[-1:]) & (0xff << nbits))
            self.addrdata = self.addrdata[:-1] + last

    def to_text(self):
        return "ECS %s/%s scope/%s" % (self.address, self.srclen,
                                       self.scopelen)

    def to_wire(self, file):
        """Opt type and len are handled by renderer"""
        file.write(struct.pack('!H', self.family))
        file.write(struct.pack('!BB', self.srclen, self.scopelen))
        file.write(self.addrdata)

    @classmethod
    def from_wire(cls, otype, wire, cur, olen):
        """Opt type and len are handled by Message.from_wire"""
        family, src, scope = struct.unpack('!HBB', wire[cur:cur+4])
        cur += 4

        addrlen = int(math.ceil(src/8.0))

        if family == 1:
            af = dns.inet.AF_INET
            pad = 4 - addrlen
        elif family == 2:
            af = dns.inet.AF_INET6
            pad = 16 - addrlen
        else:
            raise ValueError('unsupported family')

        addr = dns.inet.inet_ntop(af, wire[cur:cur+addrlen] + b'\x00' * pad)
        return cls(addr, src, scope)

    def _cmp(self, other):
        if self.addrdata == other.addrdata:
            return 0
        if self.addrdata > other.addrdata:
            return 1
        return -1

_type_to_class = {
        ECS: ECSOption
}

def get_option_class(otype):
    cls = _type_to_class.get(otype)
    if cls is None:
        cls = GenericOption
    return cls


def option_from_wire(otype, wire, current, olen):
    """Build an EDNS option object from wire format

    @param otype: The option type
    @type otype: int
    @param wire: The wire-format message
    @type wire: string
    @param current: The offset in wire of the beginning of the rdata.
    @type current: int
    @param olen: The length of the wire-format option data
    @type olen: int
    @rtype: dns.edns.Option instance"""

    cls = get_option_class(otype)
    return cls.from_wire(otype, wire, current, olen)
