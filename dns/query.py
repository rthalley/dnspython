# Copyright (C) 2003-2005 Nominum, Inc.
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

"""Talk to a DNS server."""

from __future__ import generators

import errno
import select
import socket
import struct
import sys
import time

import dns.exception
import dns.inet
import dns.name
import dns.message
import dns.rdataclass
import dns.rdatatype

class UnexpectedSource(dns.exception.DNSException):
    """Raised if a query response comes from an unexpected address or port."""
    pass

class BadResponse(dns.exception.FormError):
    """Raised if a query response does not respond to the question asked."""
    pass

def _compute_expiration(timeout):
    if timeout is None:
        return None
    else:
        return time.time() + timeout
    
def _wait_for(ir, iw, ix, expiration):
    if expiration is None:
        timeout = None
    else:
        timeout = expiration - time.time()
        if timeout <= 0.0:
            raise dns.exception.Timeout
    if timeout is None:
        (r, w, x) = select.select(ir, iw, ix)
    else:
        (r, w, x) = select.select(ir, iw, ix, timeout)
    if len(r) == 0 and len(w) == 0 and len(x) == 0:
        raise dns.exception.Timeout
    
def _wait_for_readable(s, expiration):
    _wait_for([s], [], [s], expiration)
    
def _wait_for_writable(s, expiration):
    _wait_for([], [s], [s], expiration)

def udp(q, where, timeout=None, port=53, af=None, source=None, source_port=0,
        ignore_unexpected=False):
    """Return the response obtained after sending a query via UDP.

    @param q: the query
    @type q: dns.message.Message
    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param timeout: The number of seconds to wait before the query times out.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @rtype: dns.message.Message object
    @param source: source address.  The default is the IPv4 wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param ignore_unexpected: If True, ignore responses from unexpected
    sources.  The default is False.
    @type ignore_unexpected: bool"""
    
    wire = q.to_wire()
    if af is None:
        try:
            af = dns.inet.af_for_address(where)
        except:
            af = dns.inet.AF_INET
    if af == dns.inet.AF_INET:
        destination = (where, port)
        if source is not None:
            source = (source, source_port)
    elif af == dns.inet.AF_INET6:
        destination = (where, port, 0, 0)
        if source is not None:
            source = (source, source_port, 0, 0)
    s = socket.socket(af, socket.SOCK_DGRAM, 0)
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        if source is not None:
            s.bind(source)
        _wait_for_writable(s, expiration)
        s.sendto(wire, destination)
        while 1:
            _wait_for_readable(s, expiration)
            (wire, from_address) = s.recvfrom(65535)
            if from_address == destination:
                break
            if not ignore_unexpected:
                raise UnexpectedSource, \
                      'got a response from %s instead of %s' % (from_address,
                                                                destination)
    finally:
        s.close()
    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac)
    if not q.is_response(r):
        raise BadResponse
    return r

def _net_read(sock, count, expiration):
    """Read the specified number of bytes from sock.  Keep trying until we
    either get the desired amount, or we hit EOF.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    s = ''
    while count > 0:
        _wait_for_readable(sock, expiration)
        n = sock.recv(count)
        if n == '':
            raise EOFError
        count = count - len(n)
        s = s + n
    return s

def _net_write(sock, data, expiration):
    """Write the specified data to the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    current = 0
    l = len(data)
    while current < l:
        _wait_for_writable(sock, expiration)
        current += sock.send(data[current:])

def _connect(s, address):
    try:
        s.connect(address)
    except socket.error:
        (ty, v) = sys.exc_info()[:2]
        if v[0] != errno.EINPROGRESS and \
               v[0] != errno.EWOULDBLOCK and \
               v[0] != errno.EALREADY:
            raise ty, v

def tcp(q, where, timeout=None, port=53, af=None, source=None, source_port=0):
    """Return the response obtained after sending a query via TCP.

    @param q: the query
    @type q: dns.message.Message object
    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param timeout: The number of seconds to wait before the query times out.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @rtype: dns.message.Message object
    @param source: source address.  The default is the IPv4 wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int"""
    
    wire = q.to_wire()
    if af is None:
        try:
            af = dns.inet.af_for_address(where)
        except:
            af = dns.inet.AF_INET
    if af == dns.inet.AF_INET:
        destination = (where, port)
        if source is not None:
            source = (source, source_port)
    elif af == dns.inet.AF_INET6:
        destination = (where, port, 0, 0)
        if source is not None:
            source = (source, source_port, 0, 0)
    s = socket.socket(af, socket.SOCK_STREAM, 0)
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        if source is not None:
            s.bind(source)
        _connect(s, destination)

        l = len(wire)

        # copying the wire into tcpmsg is inefficient, but lets us
        # avoid writev() or doing a short write that would get pushed
        # onto the net
        tcpmsg = struct.pack("!H", l) + wire
        _net_write(s, tcpmsg, expiration)
        ldata = _net_read(s, 2, expiration)
        (l,) = struct.unpack("!H", ldata)
        wire = _net_read(s, l, expiration)
    finally:
        s.close()
    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac)
    if not q.is_response(r):
        raise BadResponse
    return r

def xfr(where, zone, rdtype=dns.rdatatype.AXFR, rdclass=dns.rdataclass.IN,
        timeout=None, port=53, keyring=None, keyname=None, relativize=True,
        af=None, lifetime=None, source=None, source_port=0, serial=0):
    """Return a generator for the responses to a zone transfer.

    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param zone: The name of the zone to transfer
    @type zone: dns.name.Name object or string
    @param rdtype: The type of zone transfer.  The default is
    dns.rdatatype.AXFR.
    @type rdtype: int or string
    @param rdclass: The class of the zone transfer.  The default is
    dns.rdatatype.IN.
    @type rdclass: int or string
    @param timeout: The number of seconds to wait for each response message.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param keyring: The TSIG keyring to use
    @type keyring: dict
    @param keyname: The name of the TSIG key to use
    @type keyname: dns.name.Name object or string
    @param relativize: If True, all names in the zone will be relativized to
    the zone origin.  It is essential that the relativize setting matches
    the one specified to dns.zone.from_xfr().
    @type relativize: bool
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @param lifetime: The total number of seconds to spend doing the transfer.
    If None, the default, then there is no limit on the time the transfer may
    take.
    @type lifetime: float
    @rtype: generator of dns.message.Message objects.
    @param source: source address.  The default is the IPv4 wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param serial: The SOA serial number to use as the base for an IXFR diff
    sequence (only meaningful if rdtype == dns.rdatatype.IXFR).
    @type serial: int"""

    if isinstance(zone, (str, unicode)):
        zone = dns.name.from_text(zone)
    q = dns.message.make_query(zone, rdtype, rdclass)
    if rdtype == dns.rdatatype.IXFR:
        rrset = dns.rrset.from_text(zone, 0, 'IN', 'SOA',
                                    '. . %u 0 0 0 0' % serial)
        q.authority.append(rrset)
    if not keyring is None:
        q.use_tsig(keyring, keyname)
    wire = q.to_wire()
    if af is None:
        try:
            af = dns.inet.af_for_address(where)
        except:
            af = dns.inet.AF_INET
    if af == dns.inet.AF_INET:
        destination = (where, port)
        if source is not None:
            source = (source, source_port)
    elif af == dns.inet.AF_INET6:
        destination = (where, port, 0, 0)
        if source is not None:
            source = (source, source_port, 0, 0)
    s = socket.socket(af, socket.SOCK_STREAM, 0)
    if source is not None:
        s.bind(source)
    expiration = _compute_expiration(lifetime)
    _connect(s, destination)
    l = len(wire)
    tcpmsg = struct.pack("!H", l) + wire
    _net_write(s, tcpmsg, expiration)
    done = False
    soa_rrset = None
    soa_count = 0
    if relativize:
        origin = zone
        oname = dns.name.empty
    else:
        origin = None
        oname = zone
    tsig_ctx = None
    first = True
    while not done:
        mexpiration = _compute_expiration(timeout)
        if mexpiration is None or mexpiration > expiration:
            mexpiration = expiration
        ldata = _net_read(s, 2, mexpiration)
        (l,) = struct.unpack("!H", ldata)
        wire = _net_read(s, l, mexpiration)
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  xfr=True, origin=origin, tsig_ctx=tsig_ctx,
                                  multi=True, first=first)
        tsig_ctx = r.tsig_ctx
        first = False
        answer_index = 0
        delete_mode = False
        expecting_SOA = False
        if soa_rrset is None:
            if not r.answer or r.answer[0].name != oname:
                raise dns.exception.FormError
            rrset = r.answer[0]
            if rrset.rdtype != dns.rdatatype.SOA:
                raise dns.exception.FormError, "first RRset is not an SOA"
            answer_index = 1
            soa_rrset = rrset.copy()
            if rdtype == dns.rdatatype.IXFR:
                if soa_rrset[0].serial == serial:
                    #
                    # We're already up-to-date.
                    #
                    done = True
                else:
                    expecting_SOA = True
        #
        # Process SOAs in the answer section (other than the initial
        # SOA in the first message).
        #
        for rrset in r.answer[answer_index:]:
            if done:
                raise dns.exception.FormError, "answers after final SOA"
            if rrset.rdtype == dns.rdatatype.SOA and rrset.name == oname:
                if expecting_SOA:
                    if rrset[0].serial != serial:
                        raise dns.exception.FormError, \
                              "IXFR base serial mismatch"
                    expecting_SOA = False
                elif rdtype == dns.rdatatype.IXFR:
                    delete_mode = not delete_mode
                if rrset == soa_rrset and not delete_mode:
                    done = True
            elif expecting_SOA:
                #
                # We made an IXFR request and are expecting another
                # SOA RR, but saw something else, so this must be an
                # AXFR response.
                #
                rdtype = dns.rdatatype.AXFR
                expecting_SOA = False
        if done and q.keyring and not r.had_tsig:
            raise dns.exception.FormError, "missing TSIG"
        yield r
    s.close()
