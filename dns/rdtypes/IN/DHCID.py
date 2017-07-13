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

import base64

import dns.exception


class DHCID(dns.rdata.Rdata):

    """DHCID record

    @ivar data: the data (the content of the RR is opaque as far as the
    DNS is concerned)
    @type data: string
    @see: RFC 4701"""

    __slots__ = ['data']

    def __init__(self, rdclass, rdtype, data, comment=None):
        super(DHCID, self).__init__(rdclass, rdtype, comment)
        self.data = data

    def to_text(self, origin=None, relativize=True, want_comment=False, **kw):
        if want_comment and self.comment:
            return '%s ;%s' % (dns.rdata._base64ify(self.data), self.comment)
        return dns.rdata._base64ify(self.data)

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True):
        chunks = []
        comment = None
        while 1:
            t = tok.get(want_comment=True).unescape()
            if t.is_eol_or_eof():
                break
            if t.is_comment():
                comment=t.value
                continue
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            chunks.append(t.value.encode())
        b64 = b''.join(chunks)
        data = base64.b64decode(b64)
        return cls(rdclass, rdtype, data, comment=comment)

    def to_wire(self, file, compress=None, origin=None):
        file.write(self.data)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        data = wire[current: current + rdlen].unwrap()
        return cls(rdclass, rdtype, data)
