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


class TSIG(dns.rdata.Rdata):
    """
    Implementation of the TSIG DNS message type, defined in RFC2845.

    @ivar algorithm: the algorithm used for the key
    @type algorithm: dns.name.Name object
    @ivar time_signed: seconds since 1-Jan-70 UTC (*48bits*)
    @type time_signed: int
    @ivar fudge: seconds of error permitted in time signed
    @type fudge: int
    @ivar mac_size: number of octets in MAC
    @type mac_size: int
    @ivar mac: defined by Algorithm Name
    @type mac: bytes
    @ivar original_id: original message ID
    @type original_id: int
    @ivar error: expanded RCODE covering TSIG processing
    @type error: int
    @ivar other_len: length, in octets, of Other Data
    @type other_len: int
    @ivar other_data: empty unless Error == BADTIME
    @type other_data: bytes"""

    __slots__ = ['algorithm', 'time_signed', 'fudge', 'mac_size', 'mac',
                 'original_id', 'error', 'other_len', 'other_data']

    def __init__(self, rdclass, rdtype, algorithm, time_signed, fudge,
                 mac_size, mac, original_id, error, other_len, other_data):
        super().__init__(rdclass, rdtype)
        object.__setattr__(self, 'algorithm', algorithm)
        object.__setattr__(self, 'time_signed', time_signed)
        object.__setattr__(self, 'fudge', fudge)
        object.__setattr__(self, 'mac_size', mac_size)
        object.__setattr__(self, 'mac', mac)
        object.__setattr__(self, 'original_id', original_id)
        object.__setattr__(self, 'error', error)
        object.__setattr__(self, 'other_len', other_len)
        if self.other_len > 65535:
            raise ValueError('TSIG Other Data is > 65535 bytes')
        object.__setattr__(self, 'other_data', other_data)

    def to_text(self, origin=None, relativize=True, **kw):
        _algorithm = self.algorithm.choose_relativity(origin, relativize)
        return '%s %d %d %d %s %d %d %d %s' % (
            str(_algorithm), self.time_signed, self.fudge, self.mac_size,
            dns.rdata._base64ify(self.mac), self.original_id, self.error,
            self.other_len, dns.rdata._base64ify(self.other_data))

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True):
        algorithm = tok.get_name()
        time_signed = tok.get_uint48()
        fudge = tok.get_uint16()
        mac_size = tok.get_uint16()
        mac = bytearray(tok.get_string())
        original_id = tok.get_uint16()
        error = tok.get_uint16()
        other_len = tok.get_uint16()
        other_data = bytearray(tok.get_string())

        return cls(rdclass, rdtype, algorithm, time_signed, fudge, mac_size,
                   mac, original_id, error, other_len, other_data)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        self.algorithm.to_wire(file, compress, origin)
        time_signed_long = self.time_signed + int(0)
        upper_time = (time_signed_long >> 32) & int(0xffff)
        lower_time = time_signed_long & int(0xffffffff)
        file.write(struct.pack("!HIHH", upper_time, lower_time, self.fudge,
                               self.mac_size))
        file.write(self.mac)
        file.write(struct.pack("!HHH", self.original_id, self.error,
                               self.other_len))
        file.write(self.other_data)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        # Field Name       Data Type      Notes
        #       --------------------------------------------------------------
        #       Algorithm Name   domain-name    Name of the algorithm
        (algorithm, cused) = dns.name.from_wire(wire[: current + rdlen],
                                                current)
        if cused >= rdlen:
            raise dns.exception.FormError
        if origin is not None:
            algorithm = algorithm.relativize(origin)
        #       Time Signed      u_int48_t      seconds since 1-Jan-70 UTC.
        current += cused
        rdlen -= cused
        (upper_time, lower_time) = struct.unpack("!HI",
                                                 wire[current: current + 6])
        time_signed = lower_time + (upper_time << 32)
        current += 6
        rdlen -= 6
        #       Fudge            u_int16_t      seconds of error permitted
        #                                       in Time Signed.
        #       MAC Size         u_int16_t      number of octets in MAC.
        (fudge, mac_size) = struct.unpack("!HH", wire[current: current + 4])
        current += 4
        rdlen -= 4
        #       MAC              octet stream   defined by Algorithm Name.
        mac = wire[current: current + mac_size]
        current += mac_size
        rdlen -= mac_size
        #       Original ID      u_int16_t      original message ID
        #       Error            u_int16_t      expanded RCODE covering
        #                                       TSIG processing.
        #       Other Len        u_int16_t      length, in octets, of
        #                                       Other Data.
        (original_id, error, other_len) = \
            struct.unpack("!HHH", wire[current: current + 6])
        current += 6
        rdlen -= 6
        #       Other Data       octet stream   empty unless Error == BADTIME
        other_data = wire[current: current + other_len].unwrap()
        current += other_len
        rdlen -= other_len

        return cls(rdclass, rdtype, algorithm, time_signed, fudge, mac_size,
                   mac, original_id, error, other_len, other_data)

    def build_digest_data(self, keyname, wire, request_mac, first):
        """
        This method builds the data needed to compute the TSIG; this is a
        partial selection of the data in the message as defined in the RFC.

        *keyname*, ``string`` name of the TSIG key used

        *wire* ``binary`` wire representation of the message to be signed

        *request_mac*, the ``binary`` representation of the MAC from the
        original request if present

        *first*, a ``bool`` defining if this message is the first message in a
        longer sequence of DNS messages (per the RFC, the first/only message is
        handled differently to the remainder)]

        Returns the ``binary`` data to be digested
        """
        # some preliminary calculations
        long_time = self.time_signed + int(0)
        upper_time = (long_time >> 32) & int(0xffff)
        lower_time = long_time & int(0xffffffff)
        time_signed = struct.pack("!HI", upper_time, lower_time)

        # construct the data required to create the TSIG; from RFC2845:
        data = b''

        # 4.1. TSIG generation on requests
        #
        # Client performs the message digest operation and appends a TSIG
        # record to the additional data section and transmits the request to
        # the server.  The client MUST store the message digest from the
        # request while awaiting an answer.  The digest components for a
        # request are:
        #
        #    DNS Message (request)
        #    TSIG Variables (request)
        #
        # Note that some older name servers will not accept requests with a
        # nonempty additional data section.  Clients SHOULD only attempt signed
        # transactions with servers who are known to support TSIG and share
        # some secret key with the client -- so, this is not a problem in
        # practice.
        #
        # 4.2. TSIG on Answers
        #
        # When a server has generated a response to a signed request, it signs
        # the response using the same algorithm and key.  The server MUST not
        # generate a signed response to an unsigned request.  The digest
        # components are:
        #
        #    Request MAC
        #    DNS Message (response)
        #    TSIG Variables (response)
        #
        # 4.3. TSIG on TSIG Error returns
        #
        # When a server detects an error relating to the key or MAC, the server
        # SHOULD send back an unsigned error message (MAC size == 0 and empty
        # MAC).  If an error is detected relating to the TSIG validity period,
        # the server SHOULD send back a signed error message.  The digest
        # components are:
        #
        #    Request MAC (if the request MAC validated)
        #    DNS Message (response)
        #    TSIG Variables (response)

        if first:
            # request mac if it exists
            ml = len(request_mac)
            if ml > 0:
                data += struct.pack('!H', ml)
                data += request_mac

            # DNS message (minus the TSIG additional data section)
            data += wire

            # 3.4.2. TSIG Variables
            #
            # Source       Field Name      Notes
            # ------------------------------------------------------------------
            # TSIG RR      NAME            Key name, in canonical wire format
            data += keyname.to_digestable()
            # TSIG RR      CLASS           (Always ANY in the current spec)
            data += struct.pack('!H', dns.rdataclass.ANY)
            # TSIG RR      TTL             (Always 0 in the current spec)
            data += struct.pack('!I', 0)
            # TSIG RDATA   Algorithm Name  in canonical wire format
            data += self.algorithm.to_digestable()
            # TSIG RDATA   Time Signed     in network byte order
            data += time_signed
            # TSIG RDATA   Fudge           in network byte order
            data += struct.pack("!H", self.fudge)
            # TSIG RDATA   Error           in network byte order
            data += struct.pack("!H", self.error)
            # TSIG RDATA   Other Len       in network byte order
            data += struct.pack("!H", self.other_len)
            # TSIG RDATA   Other Data      exactly as transmitted
            if self.other_len > 0:
                data += self.other_data
        else:
            # 4.4. TSIG on TCP connection
            #
            # A DNS TCP session can include multiple DNS envelopes.  This is,
            # fot example, commonly used by zone transfer.  Using TSIG on such a
            # connection can protect the connection from hijacking and provide
            # data integrity.  The TSIG MUST be included on the first and last
            # DNS envelopes.  It can be optionally placed on any intermediary
            # envelopes.  It is expensive to include it on every envelopes, but
            # it MUST be placed on at least every 100'th envelope.  The first
            # envelope is processed as a standard answer, and subsequent
            # messages have the following digest components:
            #
            #    Prior Digest (running)
            #    DNS Messages (any unsigned messages since the last TSIG)
            #    TSIG Timers (current message)

            # DNS message (minus the TSIG additional data section)
            data += wire
            # TSIG RDATA   Time Signed      in network byte order
            data += time_signed
            # TSIG RDATA   Fudge            in network byte order
            data += struct.pack("!H", self.fudge)

        # return the data to be signed
        return data
