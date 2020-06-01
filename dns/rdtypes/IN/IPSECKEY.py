# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2006, 2007, 2009-2011 Nominum, Inc.
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
import base64

import dns.exception
import dns.ipv4
import dns.ipv6
import dns.name


class IPSECKEY(dns.rdata.Rdata):

    """IPSECKEY record"""

    # see: RFC 4025

    __slots__ = ['precedence', 'gateway_type', 'algorithm', 'gateway', 'key']

    def __init__(self, rdclass, rdtype, precedence, gateway_type, algorithm,
                 gateway, key):
        super().__init__(rdclass, rdtype)
        if gateway_type == 0:
            if gateway != '.' and gateway is not None:
                raise SyntaxError('invalid gateway for gateway type 0')
            gateway = None
        elif gateway_type == 1:
            # check that it's OK
            dns.ipv4.inet_aton(gateway)
        elif gateway_type == 2:
            # check that it's OK
            dns.ipv6.inet_aton(gateway)
        elif gateway_type == 3:
            pass
        else:
            raise SyntaxError(
                'invalid IPSECKEY gateway type: %d' % gateway_type)
        object.__setattr__(self, 'precedence', precedence)
        object.__setattr__(self, 'gateway_type', gateway_type)
        object.__setattr__(self, 'algorithm', algorithm)
        object.__setattr__(self, 'gateway', gateway)
        object.__setattr__(self, 'key', key)

    def to_text(self, origin=None, relativize=True, **kw):
        if self.gateway_type == 0:
            gateway = '.'
        elif self.gateway_type == 1:
            gateway = self.gateway
        elif self.gateway_type == 2:
            gateway = self.gateway
        elif self.gateway_type == 3:
            gateway = str(self.gateway.choose_relativity(origin, relativize))
        else:
            raise ValueError('invalid gateway type')
        return '%d %d %d %s %s' % (self.precedence, self.gateway_type,
                                   self.algorithm, gateway,
                                   dns.rdata._base64ify(self.key))

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True,
                  relativize_to=None):
        precedence = tok.get_uint8()
        gateway_type = tok.get_uint8()
        algorithm = tok.get_uint8()
        if gateway_type == 3:
            gateway = tok.get_name(origin, relativize, relativize_to)
        else:
            gateway = tok.get_string()
        chunks = []
        while 1:
            t = tok.get().unescape()
            if t.is_eol_or_eof():
                break
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            chunks.append(t.value.encode())
        b64 = b''.join(chunks)
        key = base64.b64decode(b64)
        return cls(rdclass, rdtype, precedence, gateway_type, algorithm,
                   gateway, key)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        header = struct.pack("!BBB", self.precedence, self.gateway_type,
                             self.algorithm)
        file.write(header)
        if self.gateway_type == 0:
            pass
        elif self.gateway_type == 1:
            file.write(dns.ipv4.inet_aton(self.gateway))
        elif self.gateway_type == 2:
            file.write(dns.ipv6.inet_aton(self.gateway))
        elif self.gateway_type == 3:
            self.gateway.to_wire(file, None, origin, False)
        else:
            raise ValueError('invalid gateway type')
        file.write(self.key)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        if rdlen < 3:
            raise dns.exception.FormError
        header = struct.unpack('!BBB', wire[current: current + 3])
        gateway_type = header[1]
        current += 3
        rdlen -= 3
        if gateway_type == 0:
            gateway = None
        elif gateway_type == 1:
            gateway = dns.ipv4.inet_ntoa(wire[current: current + 4])
            current += 4
            rdlen -= 4
        elif gateway_type == 2:
            gateway = dns.ipv6.inet_ntoa(wire[current: current + 16])
            current += 16
            rdlen -= 16
        elif gateway_type == 3:
            (gateway, cused) = dns.name.from_wire(wire[: current + rdlen],
                                                  current)
            current += cused
            rdlen -= cused
        else:
            raise dns.exception.FormError('invalid IPSECKEY gateway type')
        key = wire[current: current + rdlen].unwrap()
        if origin is not None and gateway_type == 3:
            gateway = gateway.relativize(origin)
        return cls(rdclass, rdtype, header[0], gateway_type, header[2],
                   gateway, key)
