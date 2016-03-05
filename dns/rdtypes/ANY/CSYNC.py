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

import dns.exception
import dns.rdata
import dns.rdatatype
import dns.name


class CSYNC(dns.rdata.Rdata):

    __slots__ = ['soa', 'flags', 'windows']

    def __init__(self, rdclass, rdtype, soa, flags, windows):
        super(CSYNC, self).__init__(rdclass, rdtype)
        self.soa = soa
        self.flags = flags
        self.windows = windows

    def to_text(self, origin=None, relativize=True, **kw):
        text = ''
        for (window, bitmap) in self.windows:
            bits = []
            for i in xrange(0, len(bitmap)):
                byte = ord(bitmap[i])
                for j in xrange(0, 8):
                    if byte & (0x80 >> j):
                        bits.append(dns.rdatatype.to_text(window * 256 + \
                                                          i * 8 + j))
            text += (' ' + ' '.join(bits))
        return '%s %s%s' % (self.soa, self.flags, text)


    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        soa = tok.get_name()
        flags = tok.get_name()
        rdtypes = []
        while 1:
            token = tok.get().unescape()
            if token.is_eol_or_eof():
                break
            nrdtype = dns.rdatatype.from_text(token.value)
            if nrdtype == 0:
                raise dns.exception.SyntaxError("CSYNC with bit 0")
            if nrdtype > 65535:
                raise dns.exception.SyntaxError("CSYNC with bit > 65535")
            rdtypes.append(nrdtype)
        rdtypes.sort()
        window = 0
        octets = 0
        prior_rdtype = 0
        bitmap = ['\0'] * 32
        windows = []
        for nrdtype in rdtypes:
            if nrdtype == prior_rdtype:
                continue
            prior_rdtype = nrdtype
            new_window = nrdtype // 256
            if new_window != window:
                windows.append((window, ''.join(bitmap[0:octets])))
                bitmap = ['\0'] * 32
                window = new_window
            offset = nrdtype % 256
            byte = offset // 8
            bit = offset % 8
            octets = byte + 1
            bitmap[byte] = chr(ord(bitmap[byte]) | (0x80 >> bit))
        windows.append((window, ''.join(bitmap[0:octets])))
        return cls(rdclass, rdtype, soa, flags, windows)

    def to_wire(self, file, compress = None, origin = None):
        self.soa.to_wire(file, None, origin)
        self.flags.to_wire(file,None,origin)
        for (window, bitmap) in self.windows:
            file.write(chr(window))
            file.write(chr(len(bitmap)))
            file.write(bitmap)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):

        soa = int(wire[current : current + 4].unwrap().encode('hex_codec'),16)
        current += 4
        rdlen -=4

        flags = int(wire[current:current+2].unwrap().encode('hex_codec'),16)
        current += 2
        rdlen -=2

        windows = []
        while rdlen > 0:
            if rdlen < 3:
                raise dns.exception.FormError("CSYNC too short")
            window = ord(wire[current])
            octets = ord(wire[current + 1])
            if octets == 0 or octets > 32:
                raise dns.exception.FormError("bad CSYNC octets")
            current += 2
            rdlen -= 2
            if rdlen < octets:
                raise dns.exception.FormError("bad CSYNC bitmap length")
            bitmap = wire[current : current + octets].unwrap()
            current += octets
            rdlen -= octets
            windows.append((window, bitmap))

        return cls(rdclass, rdtype, soa, flags, windows)
