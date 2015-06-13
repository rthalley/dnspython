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
import dns.tokenizer
import dns.util

class CAA(dns.rdata.Rdata):
    """CAA (Certification Authority Authorization) record

    @ivar flags: the flags
    @type flags: int
    @ivar tag: the tag
    @type tag: string
    @ivar value: the value
    @type value: string
    @see: RFC 6844"""

    __slots__ = ['flags', 'tag', 'value']

    def __init__(self, rdclass, rdtype, flags, tag, value):
        super(CAA, self).__init__(rdclass, rdtype)
        self.flags = flags
        self.tag = tag
        self.value = value

    def to_text(self, origin=None, relativize=True, **kw):
        return '%u %s "%s"' % (self.flags,
                               dns.rdata._escapify(self.tag),
                               dns.rdata._escapify(self.value))

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        flags = tok.get_uint8()
        tag = tok.get_string()
        if len(tag) > 255:
            raise dns.exception.SyntaxError("tag too long")
        if not tag.isalnum():
            raise dns.exception.SyntaxError("tag is not alphanumeric")
        value = tok.get_string()
        return cls(rdclass, rdtype, flags, tag, value)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        dns.util.write_uint8(file, self.flags)
        l = len(self.tag)
        assert l < 256
        dns.util.write_uint8(file, l)
        file.write(self.tag.encode('latin_1'))
        file.write(self.value.encode('latin_1'))

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (flags, l) = struct.unpack('!BB', wire[current : current + 2])
        current += 2
        tag = wire[current : current + l].decode('latin_1')
        value = wire[current + l:current + rdlen - 2].decode('latin_1')
        return cls(rdclass, rdtype, flags, tag, value)
