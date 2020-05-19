# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""trio async I/O library query support"""

import socket
import struct
import trio
import trio.socket  # type: ignore

import dns.exception
import dns.inet
import dns.name
import dns.message
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype

# import query symbols for compatibility and brevity
from dns.query import ssl, UnexpectedSource, BadResponse

# Function used to create a socket.  Can be overridden if needed in special
# situations.
socket_factory = trio.socket.socket

async def send_udp(sock, what, destination):
    """Asynchronously send a DNS message to the specified UDP socket.

    *sock*, a ``trio.socket``.

    *what*, a ``bytes`` or ``dns.message.Message``, the message to send.

    *destination*, a destination tuple appropriate for the address family
    of the socket, specifying where to send the query.

    Returns an ``(int, float)`` tuple of bytes sent and the sent time.
    """

    if isinstance(what, dns.message.Message):
        what = what.to_wire()
    sent_time = trio.current_time()
    n = await sock.sendto(what, destination)
    return (n, sent_time)


async def receive_udp(sock, destination, ignore_unexpected=False,
                      one_rr_per_rrset=False, keyring=None, request_mac=b'',
                      ignore_trailing=False):
    """Asynchronously read a DNS message from a UDP socket.

    *sock*, a ``trio.socket``.

    *destination*, a destination tuple appropriate for the address family
    of the socket, specifying where the associated query was sent.

    *ignore_unexpected*, a ``bool``.  If ``True``, ignore responses from
    unexpected sources.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *request_mac*, a ``bytes``, the MAC of the request (for TSIG).

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    Raises if the message is malformed, if network errors occur, of if
    there is a timeout.

    Returns a ``dns.message.Message`` object.
    """

    wire = b''
    while True:
        (wire, from_address) = await sock.recvfrom(65535)
        if dns.query._addresses_equal(sock.family, from_address,
                                      destination) or \
           (dns.inet.is_multicast(destination[0]) and
            from_address[1:] == destination[1:]):
            break
        if not ignore_unexpected:
            raise UnexpectedSource('got a response from '
                                   '%s instead of %s' % (from_address,
                                                         destination))
    received_time = trio.current_time()
    r = dns.message.from_wire(wire, keyring=keyring, request_mac=request_mac,
                              one_rr_per_rrset=one_rr_per_rrset,
                              ignore_trailing=ignore_trailing)
    return (r, received_time)

async def udp(q, where, port=53, source=None, source_port=0,
              ignore_unexpected=False, one_rr_per_rrset=False,
              ignore_trailing=False):
    """Asynchronously return the response obtained after sending a query
    via UDP.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``str`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *ignore_unexpected*, a ``bool``.  If ``True``, ignore responses from
    unexpected sources.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    Returns a ``dns.message.Message``.
    """

    wire = q.to_wire()
    (af, destination, source) = \
        dns.query._destination_and_source(None, where, port, source,
                                          source_port)
    with socket_factory(af, socket.SOCK_DGRAM, 0) as s:
        received_time = None
        sent_time = None
        if source is not None:
            await s.bind(source)
        (_, sent_time) = await send_udp(s, wire, destination)
        (r, received_time) = await receive_udp(s, destination,
                                               ignore_unexpected,
                                               one_rr_per_rrset, q.keyring,
                                               q.mac, ignore_trailing)
        if not q.is_response(r):
            raise BadResponse
        r.time = received_time - sent_time
        return r

# pylint: disable=redefined-outer-name

async def send_stream(stream, what):
    """Asynchronously send a DNS message to the specified stream.

    *stream*, a ``trio.abc.Stream``.

    *what*, a ``bytes`` or ``dns.message.Message``, the message to send.

    Returns an ``(int, float)`` tuple of bytes sent and the sent time.
    """

    if isinstance(what, dns.message.Message):
        what = what.to_wire()
    l = len(what)
    # copying the wire into tcpmsg is inefficient, but lets us
    # avoid writev() or doing a short write that would get pushed
    # onto the net
    stream_message = struct.pack("!H", l) + what
    sent_time = trio.current_time()
    await stream.send_all(stream_message)
    return (len(stream_message), sent_time)

async def _read_exactly(stream, count):
    """Read the specified number of bytes from stream.  Keep trying until we
    either get the desired amount, or we hit EOF.
    """
    s = b''
    while count > 0:
        n = await stream.receive_some(count)
        if n == b'':
            raise EOFError
        count = count - len(n)
        s = s + n
    return s

async def receive_stream(stream, one_rr_per_rrset=False, keyring=None,
                         request_mac=b'', ignore_trailing=False):
    """Read a DNS message from a stream.

    *stream*, a ``trio.abc.Stream``.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *request_mac*, a ``bytes``, the MAC of the request (for TSIG).

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    Raises if the message is malformed, if network errors occur, of if
    there is a timeout.

    Returns a ``dns.message.Message`` object.
    """

    ldata = await _read_exactly(stream, 2)
    (l,) = struct.unpack("!H", ldata)
    wire = await _read_exactly(stream, l)
    received_time = trio.current_time()
    r = dns.message.from_wire(wire, keyring=keyring, request_mac=request_mac,
                              one_rr_per_rrset=one_rr_per_rrset,
                              ignore_trailing=ignore_trailing)
    return (r, received_time)

async def stream(q, where, tls=False, port=None, source=None, source_port=0,
                 one_rr_per_rrset=False, ignore_trailing=False,
                 ssl_context=None, server_hostname=None):
    """Return the response obtained after sending a query using TCP or TLS.

    *q*, a ``dns.message.Message``, the query to send.

    *where*, a ``str`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *tls*, a ``bool``.  If ``False``, the default, the query will be
    sent using TCP and *port* will default to 53.  If ``True``, the
    query is sent using TLS, and *port* will default to 853.

    *port*, an ``int``, the port send the message to.  The default is as
    specified in the description for *tls*.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    *ssl_context*, an ``ssl.SSLContext``, the context to use when establishing
    a TLS connection. If ``None``, the default, creates one with the default
    configuration.  If this value is not ``None``, then the *tls* parameter
    is treated as if it were ``True`` regardless of its value.

    *server_hostname*, a ``str`` containing the server's hostname.  The
    default is ``None``, which means that no hostname is known, and if an
    SSL context is created, hostname checking will be disabled.

    Returns a ``dns.message.Message``.
    """

    if ssl_context is not None:
        tls = True
    if port is None:
        if tls:
            port = 853
        else:
            port = 53
    wire = q.to_wire()
    (af, destination, source) = \
        dns.query._destination_and_source(None, where, port, source,
                                          source_port)
    with socket_factory(af, socket.SOCK_STREAM, 0) as s:
        begin_time = trio.current_time()
        if source is not None:
            await s.bind(source)
        await s.connect(destination)
        stream = trio.SocketStream(s)
        if tls and ssl_context is None:
            ssl_context = ssl.create_default_context()
            if server_hostname is None:
                ssl_context.check_hostname = False
        if ssl_context:
            stream = trio.SSLStream(stream, ssl_context,
                                    server_hostname=server_hostname)
        async with stream:
            await send_stream(stream, wire)
            (r, received_time) = await receive_stream(stream, one_rr_per_rrset,
                                                      q.keyring, q.mac,
                                                      ignore_trailing)
            if not q.is_response(r):
                raise BadResponse
            r.time = received_time - begin_time
            return r
