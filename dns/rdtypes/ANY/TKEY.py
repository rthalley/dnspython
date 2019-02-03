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


class TKEY(dns.rdata.Rdata):
    """
    Implementation of the TKEY DNS message type, defined in RFC2930.

    @ivar algorithm: the algorithm used for the key
    @type algorithm: dns.name.Name object
    @ivar inception: start of validity interval for this keying material
    @type inception: int
    @ivar expiration: end of validity interval for this keying material
    @type expiration: int
    @ivar mode: scheme for key agreement or the purpose of the TKEY message
    @type mode: int
    @ivar error: the error code
    @type error: int
    @ivar key_size: size of the key exchange data in octets
    @type key_size: int
    @ivar key_data: key exchange data
    @type key_data: bytes
    @ivar other_size: reserved for future use
    @type other_size: int
    @ivar other_data: reserved for future use
    @type other_data: bytes"""

    __slots__ = ['algorithm', 'inception', 'expiration', 'mode', 'error',
                 'key_size', 'key_data', 'other_size', 'other_data']

    def __init__(self, rdclass, rdtype, algorithm, inception, expiration,
                 mode, error, key_size, key_data, other_size, other_data):
        super(TKEY, self).__init__(rdclass, rdtype)
        object.__setattr__(self, 'algorithm', algorithm)
        object.__setattr__(self, 'inception', inception)
        object.__setattr__(self, 'expiration', expiration)
        object.__setattr__(self, 'mode', mode)
        object.__setattr__(self, 'error', error)
        object.__setattr__(self, 'key_size', key_size)
        object.__setattr__(self, 'key_data', key_data)
        object.__setattr__(self, 'other_size', other_size)
        object.__setattr__(self, 'other_data', other_data)

    def to_text(self, origin=None, relativize=True, **kw):
        _algorithm = self.algorithm.choose_relativity(origin, relativize)
        return '%s %d %d %d %d %d %s %d %s' % (
            str(_algorithm), self.inception, self.expiration, self.mode,
            self.error, self.key_size, dns.rdata._base64ify(self.key_data),
            self.other_size, dns.rdata._base64ify(self.other_data))

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True):
        algorithm = tok.get_name()
        inception = tok.get_uint32()
        expiration = tok.get_uint32()
        mode = tok.get_uint16()
        error = tok.get_uint16()
        key_size = tok.get_uint16()
        key_data = bytearray(tok.get_string())
        other_size = tok.get_uint16()
        other_data = bytearray(tok.get_string())

        return cls(rdclass, rdtype, algorithm, inception, expiration, mode,
                   error, key_size, key_data, other_size, other_data)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        self.algorithm.to_wire(file, compress, origin)
        file.write(struct.pack("!IIHHH", self.inception, self.expiration,
                               self.mode, self.error, self.key_size))
        file.write(self.key_data)
        file.write(struct.pack("!H", self.other_size))
        file.write(self.other_data)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        (algorithm, cused) = dns.name.from_wire(wire[: current + rdlen],
                                                current)
        if cused >= rdlen:
            raise dns.exception.FormError
        if origin is not None:
            algorithm = algorithm.relativize(origin)

        # advance the pointer and consume the first block of data
        current += cused
        rdlen -= cused
        block1 = struct.unpack("!IIHH", wire[current: current + 12])
        current += 12
        rdlen -= 12
        key_size = struct.unpack("!H", wire[current: current + 2])[0]
        current += 2
        rdlen -= 2
        key_data = wire[current: current + key_size].unwrap()
        current += key_size
        rdlen -= key_size
        other_size = struct.unpack("!H", wire[current: current + 2])[0]
        current += 2
        rdlen -= 2
        other_data = wire[current: current + other_size].unwrap()

        return cls(rdclass, rdtype, algorithm, block1[0], block1[1], block1[2],
                   block1[3], key_size, key_data, other_size, other_data)

    # Constants for the mode field - from RFC 2930:
    # 2.5 The Mode Field
    #
    #    The mode field specifies the general scheme for key agreement or
    #    the purpose of the TKEY DNS message.  Servers and resolvers
    #    supporting this specification MUST implement the Diffie-Hellman key
    #    agreement mode and the key deletion mode for queries.  All other
    #    modes are OPTIONAL.  A server supporting TKEY that receives a TKEY
    #    request with a mode it does not support returns the BADMODE error.
    #    The following values of the Mode octet are defined, available, or
    #    reserved:
    #
    #          Value    Description
    #          -----    -----------
    #           0        - reserved, see section 7
    #           1       server assignment
    #           2       Diffie-Hellman exchange
    #           3       GSS-API negotiation
    #           4       resolver assignment
    #           5       key deletion
    #          6-65534   - available, see section 7
    #          65535     - reserved, see section 7
    SERVER_ASSIGNMENT = 1
    DIFFIE_HELLMAN_EXCHANGE = 2
    GSSAPI_NEGOTIATION = 3
    RESOLVER_ASSIGNMENT = 4
    KEY_DELETION = 5

    # additional errors relating to TKEY records - from RFC 2930:
    # 2.6 The Error Field
    #
    #    The error code field is an extended RCODE.  The following values are
    #    defined:
    #
    #          Value   Description
    #          -----   -----------
    #           0       - no error
    #           1-15   a non-extended RCODE
    #           16     BADSIG   (TSIG)
    #           17     BADKEY   (TSIG)
    #           18     BADTIME  (TSIG)
    #           19     BADMODE
    #           20     BADNAME
    #           21     BADALG
    #
    #    When the TKEY Error Field is non-zero in a response to a TKEY query,
    #    the DNS header RCODE field indicates no error. However, it is
    #    possible if a TKEY is spontaneously included in a response the TKEY
    #    RR and DNS header error field could have unrelated non-zero error
    #    codes.
    BADMODE = 19
    BADNAME = 20
    BADALG = 21
