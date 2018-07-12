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

import dns.exception
import dns.ipv4
import dns.rdata
import dns.tokenizer

from ._compat import binary_type

class DYNC(dns.rdata.Rdata):

    """DYNC record.

    @ivar pool: dynamic pool address
    @type pool: string"""

    __slots__ = ['pool']

    def __init__(self, rdclass, rdtype, pool):
        super(DYNC, self).__init__(rdclass, rdtype)
        self.pool = pool

    def to_text(self, origin=None, relativize=True, **kw):
        return self.pool

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True):
        pool = tok.get_identifier()
        tok.get_eol()
        return cls(rdclass, rdtype, pool)

    def to_wire(self, file, compress=None, origin=None):
        file.write(dns.inet.inet_pton(dns.inet.AF_INET6, self.pool))

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        pool = wire[current: current + rdlen].unwrap()
        return cls(rdclass, rdtype, pool)
