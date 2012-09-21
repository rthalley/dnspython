# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND BobNovas DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL BobNovas BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import struct

import dns.rdata
import dns.rdatatype

class TLSA(dns.rdata.Rdata):
    """TLSA record

    @ivar cert_usage: Certificate usage
    @type cert_usage: int
    @ivar selector: which part of the TLS certificate is matched against the association data
    @type selector: int
    @ivar matching_type: how the certificate association is presented
    @type matching_type: int
    @ivar cert_assoc_data: the certificate assocation data field
    @type cert_assoc_data: string
    @see: rfc6698.txt"""

    __slots__ = ['cert_usage', 'selector', 'matching_type', 'cert_assoc_data']

    def __init__(self, rdclass, rdtype, cert_usage, selector,
                 matching_type, cert_assoc_data):
        super(TLSA, self).__init__(rdclass, rdtype)
        self.cert_usage = cert_usage
        self.selector = selector
        self.matching_type = matching_type
        self.cert_assoc_data = cert_assoc_data

    def to_text(self, origin=None, relativize=True, **kw):
        return '%d %d %d %s' % (self.cert_usage,
                             self.selector,
                             self.matching_type,
                             dns.rdata._hexify(self.cert_assoc_data,
                                               chunksize=128))

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        cert_usage = tok.get_uint8()
        selector = tok.get_uint8()
        matching_type = tok.get_uint8()
        chunks = []
        while 1:
            t = tok.get().unescape()
            if t.is_eol_or_eof():
                break
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            chunks.append(t.value)
        cert_assoc_data = ''.join(chunks)
        cert_assoc_data = cert_assoc_data.decode('hex_codec')
        return cls(rdclass, rdtype, cert_usage, selector, matching_type, cert_assoc_data)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        header = struct.pack("!BBB", self.cert_usage, self.selector, self.matching_type)
        file.write(header)
        file.write(self.cert_assoc_data)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        header = struct.unpack("!BBB", wire[current : current + 3])
        current += 3
        rdlen -= 3
        cert_assoc_data = wire[current : current + rdlen].unwrap()
        return cls(rdclass, rdtype, header[0], header[1], header[2], cert_assoc_data)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        hs = struct.pack("!BBB", self.cert_usage, self.selector, self.matching_type)
        ho = struct.pack("!BBB", other.cert_usage, other.selector, other.matching_type)
        v = cmp(hs, ho)
        if v == 0:
            v = cmp(self.cert_assoc_data, other.cert_assoc_data)
        return v
