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

import struct

import dns.dnssec
import dns.exception
import dns.rdata
import dns.rdatatype

class RRSIG(dns.rdata.Rdata):
    """CSYNC record

    @ivar soa_serial: copy of child serial
    @type soa_serial: int
    @ivar flags: flags
    @type flags: int
    @ivar windows: the windowed bitmap list
    @type windows: list of (window number, string) tuples"""
    
    """CSYNC is defined in RFC 7477"""
    
    __slots__ = ['soa_serial', 'flags', 'windows']

    def __init__(self, soa_serial, flags, windows):
        super(CSYNC, self).__init__(rdclass, rdtype, soa_serial, flags, windows)
        self.soa_serial = soa_serial
        self.flags = flags
        self.windows = windows

    def to_text(self, origin=None, relativize=True, **kw):
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
        return '%d %d %s' % (self.soa_serial, self.flags, text)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        soa_serial = tok.get_uint32()
        flags = tok.get_uint16()
        rdtypes = []
        while 1:
            token = tok.get().unescape()
            if token.is_eol_or_eof():
                break
            nrdtype = dns.rdatatype.from_text(token.value)
            if nrdtype == 0:
                raise dns.exception.SyntaxError("NSEC with bit 0")
            if nrdtype > 65535:
                raise dns.exception.SyntaxError("NSEC with bit > 65535")
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
                windows.append((window, bytes(bitmap[0:octets])))
                bitmap = bytearray(32)
                window = new_window
            offset = nrdtype % 256
            byte = offset // 8
            bit = offset % 8
            octets = byte + 1
            bitmap[byte] = bitmap[byte] | (0x80 >> bit)
        windows.append((window, bytes(bitmap[0:octets])))
        return cls(rdclass, rdtype, soa_serial, flags, windows)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        file.write(struct.pack("!IH", self.soa_serial, self.flags))
        for (window, bitmap) in self.windows:
            dns.util.write_uint8(file, window)
            dns.util.write_uint8(file, len(bitmap))
            file.write(bitmap)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        if rdlen < 4:
            raise dns.exception.FormError('CSYNC RR is shorter than 4 octets')
        (soa_serial, flags) = struct.unpack('!IH', wire[current : current + 6])
        current += 6
        rdlen -= 6
        windows = []
        while rdlen > 0:
            if rdlen < 3:
                raise dns.exception.FormError("NSEC too short")
            window = wire[current]
            octets = wire[current + 1]
            if octets == 0 or octets > 32:
                raise dns.exception.FormError("bad NSEC octets")
            current += 2
            rdlen -= 2
            if rdlen < octets:
                raise dns.exception.FormError("bad NSEC bitmap length")
            bitmap = wire[current : current + octets].unwrap()
            current += octets
            rdlen -= octets
            windows.append((window, bitmap))
        if not origin is None:
            next = next.relativize(origin)
        return cls(rdclass, rdtype, soa_serial, flags, windows)

    from_wire = classmethod(from_wire)
  