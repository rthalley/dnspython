# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import struct

import dns.immutable
import dns.rdata
import dns.rdatatype
import dns.rdtypes.util


schemes = {
    0: "null",
    1: "NOTIFY",
}
schemes_by_mnemonic = {v: k for k, v in schemes.items()}


def _scheme_from_text(scheme):
    return schemes_by_mnemonic[scheme]


def _scheme_to_text(scheme):
    return schemes[scheme]


@dns.immutable.immutable
class DSYNC(dns.rdata.Rdata):
    """DSYNC record"""

    # see: draft-ietf-dnsop-generalized-notify

    __slots__ = ["rrtype", "scheme", "port", "target"]

    def __init__(self, rdclass, rdtype, rrtype, scheme, port, target):
        super().__init__(rdclass, rdtype)
        self.rrtype = self._as_uint16(rrtype)
        self.scheme = self._as_uint8(scheme)
        self.port = self._as_uint16(port)
        self.target = self._as_name(target)

    def to_text(self, origin=None, relativize=True, **kw):
        target = self.target.choose_relativity(origin, relativize)
        return "%s %s %d %s" % (
            dns.rdatatype.to_text(self.rrtype),
            _scheme_to_text(self.scheme),
            self.port,
            target,
        )

    @classmethod
    def from_text(
        cls, rdclass, rdtype, tok, origin=None, relativize=True, relativize_to=None
    ):
        rrtype = dns.rdatatype.from_text(tok.get_string())
        scheme = _scheme_from_text(tok.get_string())
        port = tok.get_uint16()
        target = tok.get_name(origin, relativize, relativize_to)
        return cls(rdclass, rdtype, rrtype, scheme, port, target)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        three_ints = struct.pack("!HBH", self.rrtype, self.scheme, self.port)
        file.write(three_ints)
        self.target.to_wire(file, None, origin, False)

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None):
        (rrtype, scheme, port) = parser.get_struct("!HBH")
        target = parser.get_name(origin)
        return cls(rdclass, rdtype, rrtype, scheme, port, target)
