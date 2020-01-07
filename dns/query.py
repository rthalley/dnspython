# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
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
import os
import select
import socket
import struct
import sys
import time
import base64
import ipaddress
import urllib.parse

import dns.exception
import dns.inet
import dns.name
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype

import requests
from requests_toolbelt.adapters.source import SourceAddressAdapter
from requests_toolbelt.adapters.host_header_ssl import HostHeaderSSLAdapter

try:
    import ssl
except ImportError:
    class ssl(object):
        class WantReadException(Exception):
            pass
        class WantWriteException(Exception):
            pass
        class SSLSocket(object):
            pass
        def create_default_context(self, *args, **kwargs):
            raise Exception('no ssl support')

# Function used to create a socket.  Can be overridden if needed in special
# situations.
socket_factory = socket.socket

class UnexpectedSource(dns.exception.DNSException):
    """A DNS query response came from an unexpected address or port."""


class BadResponse(dns.exception.FormError):
    """A DNS query response does not respond to the question asked."""


class TransferError(dns.exception.DNSException):
    """A zone transfer response got a non-zero rcode."""

    def __init__(self, rcode):
        message = 'Zone transfer error: %s' % dns.rcode.to_text(rcode)
        super(TransferError, self).__init__(message)
        self.rcode = rcode


def _compute_expiration(timeout):
    if timeout is None:
        return None
    else:
        return time.time() + timeout

# This module can use either poll() or select() as the "polling backend".
#
# A backend function takes an fd, bools for readability, writablity, and
# error detection, and a timeout.

def _poll_for(fd, readable, writable, error, timeout):
    """Poll polling backend."""

    event_mask = 0
    if readable:
        event_mask |= select.POLLIN
    if writable:
        event_mask |= select.POLLOUT
    if error:
        event_mask |= select.POLLERR

    pollable = select.poll()
    pollable.register(fd, event_mask)

    if timeout:
        event_list = pollable.poll(timeout * 1000)
    else:
        event_list = pollable.poll()

    return bool(event_list)


def _select_for(fd, readable, writable, error, timeout):
    """Select polling backend."""

    rset, wset, xset = [], [], []

    if readable:
        rset = [fd]
    if writable:
        wset = [fd]
    if error:
        xset = [fd]

    if timeout is None:
        (rcount, wcount, xcount) = select.select(rset, wset, xset)
    else:
        (rcount, wcount, xcount) = select.select(rset, wset, xset, timeout)

    return bool((rcount or wcount or xcount))


def _wait_for(fd, readable, writable, error, expiration):
    # Use the selected polling backend to wait for any of the specified
    # events.  An "expiration" absolute time is converted into a relative
    # timeout.

    done = False
    while not done:
        if expiration is None:
            timeout = None
        else:
            timeout = expiration - time.time()
            if timeout <= 0.0:
                raise dns.exception.Timeout
        try:
            if isinstance(fd, ssl.SSLSocket) and readable and fd.pending() > 0:
                return True
            if not _polling_backend(fd, readable, writable, error, timeout):
                raise dns.exception.Timeout
        except OSError as e:
            if e.args[0] != errno.EINTR:
                raise e
        done = True


def _set_polling_backend(fn):
    # Internal API. Do not use.

    global _polling_backend

    _polling_backend = fn

if hasattr(select, 'poll'):
    # Prefer poll() on platforms that support it because it has no
    # limits on the maximum value of a file descriptor (plus it will
    # be more efficient for high values).
    _polling_backend = _poll_for
else:
    _polling_backend = _select_for


def _wait_for_readable(s, expiration):
    _wait_for(s, True, False, True, expiration)


def _wait_for_writable(s, expiration):
    _wait_for(s, False, True, True, expiration)


def _addresses_equal(af, a1, a2):
    # Convert the first value of the tuple, which is a textual format
    # address into binary form, so that we are not confused by different
    # textual representations of the same address
    try:
        n1 = dns.inet.inet_pton(af, a1[0])
        n2 = dns.inet.inet_pton(af, a2[0])
    except dns.exception.SyntaxError:
        return False
    return n1 == n2 and a1[1:] == a2[1:]


def _destination_and_source(af, where, port, source, source_port,
                            default_to_inet=True):
    # Apply defaults and compute destination and source tuples
    # suitable for use in connect(), sendto(), or bind().
    if af is None:
        try:
            af = dns.inet.af_for_address(where)
        except Exception:
            if default_to_inet:
                af = dns.inet.AF_INET
    if af == dns.inet.AF_INET:
        destination = (where, port)
        if source is not None or source_port != 0:
            if source is None:
                source = '0.0.0.0'
            source = (source, source_port)
    elif af == dns.inet.AF_INET6:
        destination = (where, port, 0, 0)
        if source is not None or source_port != 0:
            if source is None:
                source = '::'
            source = (source, source_port, 0, 0)
    else:
        source = None
        destination = None
    return (af, destination, source)

def send_https(session, what, lifetime=None):
    """
    :param session: a :class:`requests.sessions.Session`
    :param what: a :class:`requests.models.Request` or
    :class:`requests.models.PreparedRequest`.
    If it's a :class:`requests.models.Request`, it will be converted
     into a :class:`requests.models.PreparedRequest`.
    :param lifetime: timeout (in seconds)
    :return: a :class:`requests.models.Response` object.
    """
    if isinstance(what, requests.models.Request):
        what = what.prepare()
    return session.send(what, timeout=lifetime)

def https(q, where, timeout=None, port=443, af=None, source=None, source_port=0,
          one_rr_per_rrset=False, ignore_trailing=False,
          session=None, path='/dns-query', post=True,
          bootstrap_address=None, verify=True):
    """Return the response obtained after sending a query via DNS-over-HTTPS.

    *q*, a ``dns.message.Message``, the query to send.

    *where*, a ``str``, the nameserver IP address or the full URL. If an IP
    address is given, the URL will be constructed using the following schema:
    https://<IP-address>:<port>/<path>.

    *timeout*, a ``float`` or ``None``, the number of seconds to
    wait before the query times out. If ``None``, the default, wait forever.

    *port*, a ``int``, the port to send the query to. The default is 443.

    *af*, an ``int``, the address family to use.  The default is ``None``,
    which causes the address family to use to be inferred from the form of
    *where*, or uses the system default.  Setting this to AF_INET or
    AF_INET6 currently has no effect.

    *source*, a ``str`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *one_rr_per_rrset*, a ``bool``. If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``. If ``True``, ignore trailing
    junk at end of the received message.

    *session*, a ``requests.session.Session``.  If provided, the session to use
    to send the queries.

    *path*, a ``str``. If *where* is an IP address, then *path* will be used to
    construct the URL to send the DNS query to.

    *post*, a ``bool``. If ``True``, the default, POST method will be used.

    *bootstrap_address*, a ``str``, the IP address to use to bypass the
    system's DNS resolver.

    *verify*, a ``str`, containing a path to a certificate file or directory.

    Returns a ``dns.message.Message``.
    """

    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port,
                                                        source, source_port,
                                                        False)
    transport_adapter = None
    headers = {
        "accept": "application/dns-message"
    }
    try:
        _ = ipaddress.ip_address(where)
        url = 'https://{}:{}{}'.format(where, port, path)
    except ValueError:
        if bootstrap_address is not None:
            split_url = urllib.parse.urlsplit(where)
            headers['Host'] = split_url.hostname
            url = where.replace(split_url.hostname, bootstrap_address)
            transport_adapter = HostHeaderSSLAdapter()
        else:
            url = where
    if source is not None:
        # set source port and source address
        transport_adapter = SourceAddressAdapter(source)

    if session:
        close_session = False
    else:
        session = requests.sessions.Session()
        close_session = True

    try:
        if transport_adapter:
            session.mount(url, transport_adapter)

        # see https://tools.ietf.org/html/rfc8484#section-4.1.1 for DoH
        # GET and POST examples
        if post:
            headers.update({
                "content-type": "application/dns-message",
                "content-length": str(len(wire))
            })
            response = session.post(url, headers=headers, data=wire,
                                    stream=True, timeout=timeout,
                                    verify=verify)
        else:
            wire = base64.urlsafe_b64encode(wire).decode('utf-8').strip("=")
            url += "?dns={}".format(wire)
            response = session.get(url, headers=headers, stream=True,
                                   timeout=timeout, verify=verify)
    finally:
        if close_session:
            session.close()

    # see https://tools.ietf.org/html/rfc8484#section-4.2.1 for info about DoH
    # status codes
    if response.status_code < 200 or response.status_code > 299:
        raise ValueError('{} responded with status code {}'
                         '\nResponse body: {}'.format(where,
                                                      response.status_code,
                                                      response.content))
    r = dns.message.from_wire(response.content,
                              keyring=q.keyring,
                              request_mac=q.request_mac,
                              one_rr_per_rrset=one_rr_per_rrset,
                              ignore_trailing=ignore_trailing)
    r.time = response.elapsed
    if not q.is_response(r):
        raise BadResponse
    return r

def send_udp(sock, what, destination, expiration=None):
    """Send a DNS message to the specified UDP socket.

    *sock*, a ``socket``.

    *what*, a ``binary`` or ``dns.message.Message``, the message to send.

    *destination*, a destination tuple appropriate for the address family
    of the socket, specifying where to send the query.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    Returns an ``(int, float)`` tuple of bytes sent and the sent time.
    """

    if isinstance(what, dns.message.Message):
        what = what.to_wire()
    _wait_for_writable(sock, expiration)
    sent_time = time.time()
    n = sock.sendto(what, destination)
    return (n, sent_time)


def receive_udp(sock, destination, expiration=None,
                ignore_unexpected=False, one_rr_per_rrset=False,
                keyring=None, request_mac=b'', ignore_trailing=False):
    """Read a DNS message from a UDP socket.

    *sock*, a ``socket``.

    *destination*, a destination tuple appropriate for the address family
    of the socket, specifying where the associated query was sent.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    *ignore_unexpected*, a ``bool``.  If ``True``, ignore responses from
    unexpected sources.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *request_mac*, a ``binary``, the MAC of the request (for TSIG).

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    Raises if the message is malformed, if network errors occur, of if
    there is a timeout.

    Returns a ``dns.message.Message`` object.
    """

    wire = b''
    while 1:
        _wait_for_readable(sock, expiration)
        (wire, from_address) = sock.recvfrom(65535)
        if _addresses_equal(sock.family, from_address, destination) or \
           (dns.inet.is_multicast(destination[0]) and
            from_address[1:] == destination[1:]):
            break
        if not ignore_unexpected:
            raise UnexpectedSource('got a response from '
                                   '%s instead of %s' % (from_address,
                                                         destination))
    received_time = time.time()
    r = dns.message.from_wire(wire, keyring=keyring, request_mac=request_mac,
                              one_rr_per_rrset=one_rr_per_rrset,
                              ignore_trailing=ignore_trailing)
    return (r, received_time)

def udp(q, where, timeout=None, port=53, af=None, source=None, source_port=0,
        ignore_unexpected=False, one_rr_per_rrset=False, ignore_trailing=False):
    """Return the response obtained after sending a query via UDP.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``text`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the
    query times out.  If ``None``, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *af*, an ``int``, the address family to use.  The default is ``None``,
    which causes the address family to use to be inferred from the form of
    *where*.  If the inference attempt fails, AF_INET is used.  This
    parameter is historical; you need never set it.

    *source*, a ``text`` containing an IPv4 or IPv6 address, specifying
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
    (af, destination, source) = _destination_and_source(af, where, port,
                                                        source, source_port)
    s = socket_factory(af, socket.SOCK_DGRAM, 0)
    received_time = None
    sent_time = None
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        if source is not None:
            s.bind(source)
        (_, sent_time) = send_udp(s, wire, destination, expiration)
        (r, received_time) = receive_udp(s, destination, expiration,
                                         ignore_unexpected, one_rr_per_rrset,
                                         q.keyring, q.mac, ignore_trailing)
    finally:
        if sent_time is None or received_time is None:
            response_time = 0
        else:
            response_time = received_time - sent_time
        s.close()
    r.time = response_time
    if not q.is_response(r):
        raise BadResponse
    return r


def _net_read(sock, count, expiration):
    """Read the specified number of bytes from sock.  Keep trying until we
    either get the desired amount, or we hit EOF.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    s = b''
    while count > 0:
        _wait_for_readable(sock, expiration)
        try:
            n = sock.recv(count)
        except ssl.SSLWantReadError:
            continue
        except ssl.SSLWantWriteError:
            _wait_for_writable(sock, expiration)
            continue
        if n == b'':
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
        try:
            current += sock.send(data[current:])
        except ssl.SSLWantReadError:
            _wait_for_readable(sock, expiration)
            continue
        except ssl.SSLWantWriteError:
            continue


def send_tcp(sock, what, expiration=None):
    """Send a DNS message to the specified TCP socket.

    *sock*, a ``socket``.

    *what*, a ``binary`` or ``dns.message.Message``, the message to send.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    Returns an ``(int, float)`` tuple of bytes sent and the sent time.
    """

    if isinstance(what, dns.message.Message):
        what = what.to_wire()
    l = len(what)
    # copying the wire into tcpmsg is inefficient, but lets us
    # avoid writev() or doing a short write that would get pushed
    # onto the net
    tcpmsg = struct.pack("!H", l) + what
    _wait_for_writable(sock, expiration)
    sent_time = time.time()
    _net_write(sock, tcpmsg, expiration)
    return (len(tcpmsg), sent_time)

def receive_tcp(sock, expiration=None, one_rr_per_rrset=False,
                keyring=None, request_mac=b'', ignore_trailing=False):
    """Read a DNS message from a TCP socket.

    *sock*, a ``socket``.

    *expiration*, a ``float`` or ``None``, the absolute time at which
    a timeout exception should be raised.  If ``None``, no timeout will
    occur.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *request_mac*, a ``binary``, the MAC of the request (for TSIG).

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    Raises if the message is malformed, if network errors occur, of if
    there is a timeout.

    Returns a ``dns.message.Message`` object.
    """

    ldata = _net_read(sock, 2, expiration)
    (l,) = struct.unpack("!H", ldata)
    wire = _net_read(sock, l, expiration)
    received_time = time.time()
    r = dns.message.from_wire(wire, keyring=keyring, request_mac=request_mac,
                              one_rr_per_rrset=one_rr_per_rrset,
                              ignore_trailing=ignore_trailing)
    return (r, received_time)

def _connect(s, address, expiration):
    try:
        s.connect(address)
    except socket.error:
        (ty, v) = sys.exc_info()[:2]

        if hasattr(v, 'errno'):
            v_err = v.errno
        else:
            v_err = v[0]
        if v_err not in [errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY]:
            raise v
        _wait_for_writable(s, expiration)
        err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            raise OSError(err, os.strerror(err)) from None


def tcp(q, where, timeout=None, port=53, af=None, source=None, source_port=0,
        one_rr_per_rrset=False, ignore_trailing=False):
    """Return the response obtained after sending a query via TCP.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``text`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the
    query times out.  If ``None``, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *af*, an ``int``, the address family to use.  The default is ``None``,
    which causes the address family to use to be inferred from the form of
    *where*.  If the inference attempt fails, AF_INET is used.  This
    parameter is historical; you need never set it.

    *source*, a ``text`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    Returns a ``dns.message.Message``.
    """

    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port,
                                                        source, source_port)
    s = socket_factory(af, socket.SOCK_STREAM, 0)
    begin_time = None
    received_time = None
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        begin_time = time.time()
        if source is not None:
            s.bind(source)
        _connect(s, destination, expiration)
        send_tcp(s, wire, expiration)
        (r, received_time) = receive_tcp(s, expiration, one_rr_per_rrset,
                                         q.keyring, q.mac, ignore_trailing)
    finally:
        if begin_time is None or received_time is None:
            response_time = 0
        else:
            response_time = received_time - begin_time
        s.close()
    r.time = response_time
    if not q.is_response(r):
        raise BadResponse
    return r


def tls(q, where, timeout=None, port=853, af=None, source=None, source_port=0,
        one_rr_per_rrset=False, ignore_trailing=False,
        ssl_context=None, server_hostname=None):
    """Return the response obtained after sending a query via TLS.

    *q*, a ``dns.message.Message``, the query to send

    *where*, a ``text`` containing an IPv4 or IPv6 address,  where
    to send the message.

    *timeout*, a ``float`` or ``None``, the number of seconds to wait before the
    query times out.  If ``None``, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 853.

    *af*, an ``int``, the address family to use.  The default is ``None``,
    which causes the address family to use to be inferred from the form of
    *where*.  If the inference attempt fails, AF_INET is used.  This
    parameter is historical; you need never set it.

    *source*, a ``text`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its own
    RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the received message.

    *ssl_context*, an ``ssl.SSLContext``, the context to use when establishing
    a TLS connection. If ``None``, the default, creates one with the default
    configuration.

    *server_hostname*, a ``text`` containing the server's hostname.  The
    default is ``None``, which means that no hostname is known, and if an
    SSL context is created, hostname checking will be disabled.

    Returns a ``dns.message.Message``.
    """

    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port,
                                                        source, source_port)
    s = socket_factory(af, socket.SOCK_STREAM, 0)
    begin_time = None
    received_time = None
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        begin_time = time.time()
        if source is not None:
            s.bind(source)
        _connect(s, destination, expiration)
        if ssl_context is None:
            ssl_context = ssl.create_default_context()
            if server_hostname is None:
                ssl_context.check_hostname = False
        s = ssl_context.wrap_socket(s, do_handshake_on_connect=False,
                                    server_hostname=server_hostname)
        while True:
            try:
                s.do_handshake()
                break
            except ssl.SSLWantReadError:
                _wait_for_readable(s, expiration)
            except ssl.SSLWantWriteError:
                _wait_for_writable(s, expiration)
        send_tcp(s, wire, expiration)
        (r, received_time) = receive_tcp(s, expiration, one_rr_per_rrset,
                                         q.keyring, q.mac, ignore_trailing)
    finally:
        if begin_time is None or received_time is None:
            response_time = 0
        else:
            response_time = received_time - begin_time
        s.close()
    r.time = response_time
    if not q.is_response(r):
        raise BadResponse
    return r


def xfr(where, zone, rdtype=dns.rdatatype.AXFR, rdclass=dns.rdataclass.IN,
        timeout=None, port=53, keyring=None, keyname=None, relativize=True,
        af=None, lifetime=None, source=None, source_port=0, serial=0,
        use_udp=False, keyalgorithm=dns.tsig.default_algorithm):
    """Return a generator for the responses to a zone transfer.

    *where*.  If the inference attempt fails, AF_INET is used.  This
    parameter is historical; you need never set it.

    *zone*, a ``dns.name.Name`` or ``text``, the name of the zone to transfer.

    *rdtype*, an ``int`` or ``text``, the type of zone transfer.  The
    default is ``dns.rdatatype.AXFR``.  ``dns.rdatatype.IXFR`` can be
    used to do an incremental transfer instead.

    *rdclass*, an ``int`` or ``text``, the class of the zone transfer.
    The default is ``dns.rdataclass.IN``.

    *timeout*, a ``float``, the number of seconds to wait for each
    response message.  If None, the default, wait forever.

    *port*, an ``int``, the port send the message to.  The default is 53.

    *keyring*, a ``dict``, the keyring to use for TSIG.

    *keyname*, a ``dns.name.Name`` or ``text``, the name of the TSIG
    key to use.

    *relativize*, a ``bool``.  If ``True``, all names in the zone will be
    relativized to the zone origin.  It is essential that the
    relativize setting matches the one specified to
    ``dns.zone.from_xfr()`` if using this generator to make a zone.

    *af*, an ``int``, the address family to use.  The default is ``None``,
    which causes the address family to use to be inferred from the form of
    *where*.  If the inference attempt fails, AF_INET is used.  This
    parameter is historical; you need never set it.

    *lifetime*, a ``float``, the total number of seconds to spend
    doing the transfer.  If ``None``, the default, then there is no
    limit on the time the transfer may take.

    *source*, a ``text`` containing an IPv4 or IPv6 address, specifying
    the source address.  The default is the wildcard address.

    *source_port*, an ``int``, the port from which to send the message.
    The default is 0.

    *serial*, an ``int``, the SOA serial number to use as the base for
    an IXFR diff sequence (only meaningful if *rdtype* is
    ``dns.rdatatype.IXFR``).

    *use_udp*, a ``bool``.  If ``True``, use UDP (only meaningful for IXFR).

    *keyalgorithm*, a ``dns.name.Name`` or ``text``, the TSIG algorithm to use.

    Raises on errors, and so does the generator.

    Returns a generator of ``dns.message.Message`` objects.
    """

    if isinstance(zone, str):
        zone = dns.name.from_text(zone)
    if isinstance(rdtype, str):
        rdtype = dns.rdatatype.from_text(rdtype)
    q = dns.message.make_query(zone, rdtype, rdclass)
    if rdtype == dns.rdatatype.IXFR:
        rrset = dns.rrset.from_text(zone, 0, 'IN', 'SOA',
                                    '. . %u 0 0 0 0' % serial)
        q.authority.append(rrset)
    if keyring is not None:
        q.use_tsig(keyring, keyname, algorithm=keyalgorithm)
    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port,
                                                        source, source_port)
    if use_udp:
        if rdtype != dns.rdatatype.IXFR:
            raise ValueError('cannot do a UDP AXFR')
        s = socket_factory(af, socket.SOCK_DGRAM, 0)
    else:
        s = socket_factory(af, socket.SOCK_STREAM, 0)
    s.setblocking(0)
    if source is not None:
        s.bind(source)
    expiration = _compute_expiration(lifetime)
    _connect(s, destination, expiration)
    l = len(wire)
    if use_udp:
        _wait_for_writable(s, expiration)
        s.send(wire)
    else:
        tcpmsg = struct.pack("!H", l) + wire
        _net_write(s, tcpmsg, expiration)
    done = False
    delete_mode = True
    expecting_SOA = False
    soa_rrset = None
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
        if mexpiration is None or \
           (expiration is not None and mexpiration > expiration):
            mexpiration = expiration
        if use_udp:
            _wait_for_readable(s, expiration)
            (wire, from_address) = s.recvfrom(65535)
        else:
            ldata = _net_read(s, 2, mexpiration)
            (l,) = struct.unpack("!H", ldata)
            wire = _net_read(s, l, mexpiration)
        is_ixfr = (rdtype == dns.rdatatype.IXFR)
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  xfr=True, origin=origin, tsig_ctx=tsig_ctx,
                                  multi=True, first=first,
                                  one_rr_per_rrset=is_ixfr)
        rcode = r.rcode()
        if rcode != dns.rcode.NOERROR:
            raise TransferError(rcode)
        tsig_ctx = r.tsig_ctx
        first = False
        answer_index = 0
        if soa_rrset is None:
            if not r.answer or r.answer[0].name != oname:
                raise dns.exception.FormError(
                    "No answer or RRset not for qname")
            rrset = r.answer[0]
            if rrset.rdtype != dns.rdatatype.SOA:
                raise dns.exception.FormError("first RRset is not an SOA")
            answer_index = 1
            soa_rrset = rrset.copy()
            if rdtype == dns.rdatatype.IXFR:
                if soa_rrset[0].serial <= serial:
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
                raise dns.exception.FormError("answers after final SOA")
            if rrset.rdtype == dns.rdatatype.SOA and rrset.name == oname:
                if expecting_SOA:
                    if rrset[0].serial != serial:
                        raise dns.exception.FormError(
                            "IXFR base serial mismatch")
                    expecting_SOA = False
                elif rdtype == dns.rdatatype.IXFR:
                    delete_mode = not delete_mode
                #
                # If this SOA RRset is equal to the first we saw then we're
                # finished. If this is an IXFR we also check that we're seeing
                # the record in the expected part of the response.
                #
                if rrset == soa_rrset and \
                        (rdtype == dns.rdatatype.AXFR or
                         (rdtype == dns.rdatatype.IXFR and delete_mode)):
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
            raise dns.exception.FormError("missing TSIG")
        yield r
    s.close()
