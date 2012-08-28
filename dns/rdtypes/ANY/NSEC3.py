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
import io
import string
import struct

import dns.exception
import dns.rdata
import dns.rdatatype
import dns.util

b32_hex_to_normal = bytes.maketrans(b'0123456789ABCDEFGHIJKLMNOPQRSTUV',
                                    b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
b32_normal_to_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                    b'0123456789ABCDEFGHIJKLMNOPQRSTUV')

# hash algorithm constants
SHA1 = 1

# flag constants
OPTOUT = 1

class NSEC3(dns.rdata.Rdata):
    """NSEC3 record

    @ivar algorithm: the hash algorithm number
    @type algorithm: int
    @ivar flags: the flags
    @type flags: int
    @ivar iterations: the number of iterations
    @type iterations: int
    @ivar salt: the salt
    @type salt: bytes
    @ivar next: the next name hash
    @type next: bytes
    @ivar windows: the windowed bitmap list
    @type windows: list of (window number, bytes) tuples"""

    __slots__ = ['algorithm', 'flags', 'iterations', 'salt', 'next', 'windows']

    def __init__(self, rdclass, rdtype, algorithm, flags, iterations, salt,
                 next, windows):
        super(NSEC3, self).__init__(rdclass, rdtype)
        self.algorithm = algorithm
        self.flags = flags
        self.iterations = iterations
        self.salt = salt
        self.next = next
        self.windows = windows

    def to_text(self, origin=None, relativize=True, **kw):
        next = base64.b32encode(self.next).translate(b32_normal_to_hex).lower()
        next = next.decode('ascii')
        if self.salt == b'':
            salt = '-'
        else:
            salt = base64.b16encode(self.salt).decode('ascii').lower()
        text = ''
        for (window, bitmap) in self.windows:
            bits = []
            for i in range(0, len(bitmap)):
                byte = bitmap[i]
                for j in range(0, 8):
                    if byte & (0x80 >> j):
                        bits.append(dns.rdatatype.to_text(window * 256 + \
                                                          i * 8 + j))
            text += (' ' + ' '.join(bits))
        return '%u %u %u %s %s%s' % (self.algorithm, self.flags, self.iterations,
                                     salt, next, text)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        algorithm = tok.get_uint8()
        flags = tok.get_uint8()
        iterations = tok.get_uint16()
        salt = tok.get_string()
        if salt == '-':
            salt = b''
        else:
            salt = bytes.fromhex(salt)
        next = tok.get_string().upper().encode('ascii')
        next = next.translate(b32_hex_to_normal)
        next = base64.b32decode(next)
        rdtypes = []
        while 1:
            token = tok.get().unescape()
            if token.is_eol_or_eof():
                break
            nrdtype = dns.rdatatype.from_text(token.value)
            if nrdtype == 0:
                raise dns.exception.SyntaxError("NSEC3 with bit 0")
            if nrdtype > 65535:
                raise dns.exception.SyntaxError("NSEC3 with bit > 65535")
            rdtypes.append(nrdtype)
        rdtypes.sort()
        window = 0
        octets = 0
        prior_rdtype = 0
        bitmap = bytearray(32)
        windows = []
        for nrdtype in rdtypes:
            if nrdtype == prior_rdtype:
                continue
            prior_rdtype = nrdtype
            new_window = nrdtype // 256
            if new_window != window:
                if octets != 0:
                    windows.append((window, bytes(bitmap[0:octets])))
                bitmap = bytearray(32)
                window = new_window
            offset = nrdtype % 256
            byte = offset // 8
            bit = offset % 8
            octets = byte + 1
            bitmap[byte] = bitmap[byte] | (0x80 >> bit)
        if octets != 0:
            windows.append((window, bytes(bitmap[0:octets])))
        return cls(rdclass, rdtype, algorithm, flags, iterations, salt, next, windows)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        l = len(self.salt)
        file.write(struct.pack("!BBHB", self.algorithm, self.flags,
                               self.iterations, l))
        file.write(self.salt)
        l = len(self.next)
        file.write(struct.pack("!B", l))
        file.write(self.next)
        for (window, bitmap) in self.windows:
            dns.util.write_uint8(file, window)
            dns.util.write_uint8(file, len(bitmap))
            file.write(bitmap)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (algorithm, flags, iterations, slen) = struct.unpack('!BBHB',
                                                             wire[current : current + 5])
        current += 5
        rdlen -= 5
        salt = wire[current : current + slen].unwrap()
        current += slen
        rdlen -= slen
        nlen = wire[current]
        current += 1
        rdlen -= 1
        next = wire[current : current + nlen].unwrap()
        current += nlen
        rdlen -= nlen
        windows = []
        while rdlen > 0:
            if rdlen < 3:
                raise dns.exception.FormError("NSEC3 too short")
            window = wire[current]
            octets = wire[current + 1]
            if octets == 0 or octets > 32:
                raise dns.exception.FormError("bad NSEC3 octets")
            current += 2
            rdlen -= 2
            if rdlen < octets:
                raise dns.exception.FormError("bad NSEC3 bitmap length")
            bitmap = wire[current : current + octets].unwrap()
            current += octets
            rdlen -= octets
            windows.append((window, bitmap))
        return cls(rdclass, rdtype, algorithm, flags, iterations, salt, next, windows)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        return self._wire_cmp(other)
