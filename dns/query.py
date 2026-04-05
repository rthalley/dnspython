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

import base64
import contextlib
import enum
import errno
import os
import random
import selectors
import socket
import struct
import time
import urllib.parse
from collections.abc import Callable
from typing import Any, cast

import dns._features
import dns._tls_util
import dns.exception
import dns.inet
import dns.message
import dns.name
import dns.quic
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.transaction
import dns.tsig
import dns.xfr

try:
    import ssl
except ImportError:
    import dns._no_ssl as ssl  # pyright: ignore


def _remaining(expiration):
    if expiration is None:
        return None
    timeout = expiration - time.time()
    if timeout <= 0.0:
        raise dns.exception.Timeout
    return timeout


def _expiration_for_this_attempt(timeout, expiration):
    if expiration is None:
        return None
    return min(time.time() + timeout, expiration)


_have_httpx = dns._features.have("doh")
if _have_httpx:
    import httpcore._backends.sync
    import httpx

    _CoreNetworkBackend = httpcore.NetworkBackend
    _CoreSyncStream = httpcore._backends.sync.SyncStream

    class _NetworkBackend(_CoreNetworkBackend):
        def __init__(self, resolver, local_port, bootstrap_address, family):
            super().__init__()
            self._local_port = local_port
            self._resolver = resolver
            self._bootstrap_address = bootstrap_address
            self._family = family

        def connect_tcp(
            self, host, port, timeout=None, local_address=None, socket_options=None
        ):  # pylint: disable=signature-differs
            addresses = []
            _, expiration = _compute_times(timeout)
            if dns.inet.is_address(host):
                addresses.append(host)
            elif self._bootstrap_address is not None:
                addresses.append(self._bootstrap_address)
            else:
                timeout = _remaining(expiration)
                family = self._family
                if local_address:
                    family = dns.inet.af_for_address(local_address)
                answers = self._resolver.resolve_name(
                    host, family=family, lifetime=timeout
                )
                addresses = answers.addresses()
            for address in addresses:
                af = dns.inet.af_for_address(address)
                if local_address is not None or self._local_port != 0:
                    if local_address is None:
                        local_address = "0.0.0.0"
                    source = dns.inet.low_level_address_tuple(
                        (local_address, self._local_port), af
                    )
                else:
                    source = None
                try:
                    sock = make_socket(af, socket.SOCK_STREAM, source)
                    attempt_expiration = _expiration_for_this_attempt(2.0, expiration)
                    _connect(
                        sock,
                        dns.inet.low_level_address_tuple((address, port), af),
                        attempt_expiration,
                    )
                    return _CoreSyncStream(sock)
                except Exception:
                    pass
            raise httpcore.ConnectError

        def connect_unix_socket(
            self, path, timeout=None, socket_options=None
        ):  # pylint: disable=signature-differs
            raise NotImplementedError

    class _HTTPTransport(httpx.HTTPTransport):  # pyright: ignore
        def __init__(
            self,
            *args,
            local_port=0,
            bootstrap_address=None,
            resolver=None,
            family=socket.AF_UNSPEC,
            **kwargs,
        ):
            if resolver is None and bootstrap_address is None:
                # pylint: disable=import-outside-toplevel,redefined-outer-name
                import dns.resolver

                resolver = dns.resolver.Resolver()
            super().__init__(*args, **kwargs)
            self._pool._network_backend = _NetworkBackend(  # type: ignore
                resolver, local_port, bootstrap_address, family
            )

else:

    class _HTTPTransport:  # pyright: ignore
        def __init__(
            self,
            *args,
            local_port=0,
            bootstrap_address=None,
            resolver=None,
            family=socket.AF_UNSPEC,
            **kwargs,
        ):
            pass

        def connect_tcp(self, host, port, timeout, local_address):
            raise NotImplementedError


have_doh = _have_httpx


def default_socket_factory(
    af: socket.AddressFamily | int,
    kind: socket.SocketKind,
    proto: int,
) -> socket.socket:
    return socket.socket(af, kind, proto)


# Function used to create a socket.  Can be overridden if needed in special
# situations.
socket_factory: Callable[
    [socket.AddressFamily | int, socket.SocketKind, int], socket.socket
] = default_socket_factory


class UnexpectedSource(dns.exception.DNSException):
    """A DNS query response came from an unexpected address or port."""


class BadResponse(dns.exception.FormError):
    """A DNS query response does not respond to the question asked."""


class NoDOH(dns.exception.DNSException):
    """DNS over HTTPS (DOH) was requested but the httpx module is not
    available."""


class NoDOQ(dns.exception.DNSException):
    """DNS over QUIC (DOQ) was requested but the aioquic module is not
    available."""


# for backwards compatibility
TransferError = dns.xfr.TransferError


def _compute_times(timeout):
    now = time.time()
    if timeout is None:
        return (now, None)
    else:
        return (now, now + timeout)


def _wait_for(fd, readable, writable, _, expiration):
    # Use the selected selector class to wait for any of the specified
    # events.  An "expiration" absolute time is converted into a relative
    # timeout.
    #
    # The unused parameter is 'error', which is always set when
    # selecting for read or write, and we have no error-only selects.

    if readable and isinstance(fd, ssl.SSLSocket) and fd.pending() > 0:
        return True
    with selectors.DefaultSelector() as sel:
        events = 0
        if readable:
            events |= selectors.EVENT_READ
        if writable:
            events |= selectors.EVENT_WRITE
        if events:
            sel.register(fd, events)  # pyright: ignore
        if expiration is None:
            timeout = None
        else:
            timeout = expiration - time.time()
            if timeout <= 0.0:
                raise dns.exception.Timeout
        if not sel.select(timeout):
            raise dns.exception.Timeout


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


def _matches_destination(af, from_address, destination, ignore_unexpected):
    # Check that from_address is appropriate for a response to a query
    # sent to destination.
    if not destination:
        return True
    if _addresses_equal(af, from_address, destination) or (
        dns.inet.is_multicast(destination[0]) and from_address[1:] == destination[1:]
    ):
        return True
    elif ignore_unexpected:
        return False
    raise UnexpectedSource(
        f"got a response from {from_address} instead of " f"{destination}"
    )


def _destination_and_source(
    where, port, source, source_port, where_must_be_address=True
):
    # Apply defaults and compute destination and source tuples
    # suitable for use in connect(), sendto(), or bind().
    af = None
    destination = None
    try:
        af = dns.inet.af_for_address(where)
        destination = where
    except Exception:
        if where_must_be_address:
            raise
        # URLs are ok so eat the exception
    if source:
        saf = dns.inet.af_for_address(source)
        if af:
            # We know the destination af, so source had better agree!
            if saf != af:
                raise ValueError(
                    "different address families for source and destination"
                )
        else:
            # We didn't know the destination af, but we know the source,
            # so that's our af.
            af = saf
    if source_port and not source:
        # Caller has specified a source_port but not an address, so we
        # need to return a source, and we need to use the appropriate
        # wildcard address as the address.
        try:
            source = dns.inet.any_for_af(af)
        except Exception:
            # we catch this and raise ValueError for backwards compatibility
            raise ValueError("source_port specified but address family is unknown")
    # Convert high-level (address, port) tuples into low-level address
    # tuples.
    if destination:
        destination = dns.inet.low_level_address_tuple((destination, port), af)
    if source:
        source = dns.inet.low_level_address_tuple((source, source_port), af)
    return (af, destination, source)


def make_socket(
    af: socket.AddressFamily | int,
    type: socket.SocketKind,
    source: Any | None = None,
) -> socket.socket:
    """Make a socket using the module's ``socket_factory``.

    :param af: Address family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :type af: ``socket.AddressFamily`` or int
    :param type: Socket type, e.g. ``socket.SOCK_DGRAM`` or
        ``socket.SOCK_STREAM``.  The ``proto`` is always 0, so datagram
        sockets are UDP and stream sockets are TCP.
    :type type: ``socket.SocketKind``
    :param source: Source address/port tuple to bind to, or ``None`` (bind
        to wildcard address and random port).
    """
    s = socket_factory(af, type, 0)
    try:
        s.setblocking(False)
        if source is not None:
            s.bind(source)
        return s
    except Exception:
        s.close()
        raise


def make_ssl_socket(
    af: socket.AddressFamily | int,
    type: socket.SocketKind,
    ssl_context: ssl.SSLContext,
    server_hostname: dns.name.Name | str | None = None,
    source: Any | None = None,
) -> ssl.SSLSocket:
    """Make an SSL socket using the module's ``socket_factory``.

    :param af: Address family: ``socket.AF_INET`` or ``socket.AF_INET6``.
    :type af: ``socket.AddressFamily`` or int
    :param type: Socket type, e.g. ``socket.SOCK_DGRAM`` or
        ``socket.SOCK_STREAM``.
    :type type: ``socket.SocketKind``
    :param ssl_context: The SSL context to use, typically created with
        :py:func:`make_ssl_context`.
    :type ssl_context: ``ssl.SSLContext``
    :param server_hostname: The hostname for server certificate validation,
        or ``None``.  Required when *ssl_context* uses hostname checking.
    :type server_hostname: :py:class:`dns.name.Name` or str or ``None``
    :param source: Source address/port tuple to bind to, or ``None`` (bind
        to wildcard address and random port).
    """
    sock = make_socket(af, type, source)
    if isinstance(server_hostname, dns.name.Name):
        server_hostname = server_hostname.to_text()
    # LGTM gets a false positive here, as our default context is OK
    return ssl_context.wrap_socket(
        sock,
        do_handshake_on_connect=False,  # lgtm[py/insecure-protocol]
        server_hostname=server_hostname,
    )


# for backwards compatibility
def _make_socket(
    af,
    type,
    source,
    ssl_context,
    server_hostname,
):
    if ssl_context is not None:
        return make_ssl_socket(af, type, ssl_context, server_hostname, source)
    else:
        return make_socket(af, type, source)


def _maybe_get_resolver(
    resolver: "dns.resolver.Resolver | None",  # pyright: ignore
) -> "dns.resolver.Resolver":  # pyright: ignore
    # We need a separate method for this to avoid overriding the global
    # variable "dns" with the as-yet undefined local variable "dns"
    # in https().
    if resolver is None:
        # pylint: disable=import-outside-toplevel,redefined-outer-name
        import dns.resolver

        resolver = dns.resolver.Resolver()
    return resolver


class HTTPVersion(enum.IntEnum):
    """Which version of HTTP should be used?

    DEFAULT will select the first version from the list [2, 1.1, 3] that
    is available.
    """

    DEFAULT = 0
    HTTP_1 = 1
    H1 = 1
    HTTP_2 = 2
    H2 = 2
    HTTP_3 = 3
    H3 = 3


def https(
    q: dns.message.Message,
    where: str,
    timeout: float | None = None,
    port: int = 443,
    source: str | None = None,
    source_port: int = 0,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    session: Any | None = None,
    path: str = "/dns-query",
    post: bool = True,
    bootstrap_address: str | None = None,
    verify: bool | str | ssl.SSLContext = True,
    resolver: "dns.resolver.Resolver | None" = None,  # pyright: ignore
    family: int = socket.AF_UNSPEC,
    http_version: HTTPVersion = HTTPVersion.DEFAULT,
) -> dns.message.Message:
    """Return the response obtained after sending a query via DNS-over-HTTPS.

    :param q: The query to send.
    :type q: :py:class:`dns.message.Message`
    :param where: The nameserver IP address or full URL.  If an IP address is
        given, the URL is constructed as
        ``https://<IP-address>:<port>/<path>``.
    :type where: str
    :param timeout: Seconds to wait before timing out.  ``None`` means wait
        forever.
    :type timeout: float or ``None``
    :param port: The port to send the query to.  Default is 443.
    :type port: int
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default is
        0.
    :type source_port: int
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :param session: If provided, the client session to use to send the
        queries.
    :type session: ``httpx.Client`` or ``None``
    :param path: If *where* is an IP address, *path* is used to construct the
        query URL.
    :type path: str
    :param post: If ``True`` (the default), use the POST method.
    :type post: bool
    :param bootstrap_address: The IP address to use to bypass resolution.
    :type bootstrap_address: str or ``None``
    :param verify: If ``True``, verify the TLS certificate using default CA
        roots; if ``False``, disable verification; if a ``str``, path to a
        certificate file or directory.
    :type verify: bool or str
    :param resolver: Resolver to use for hostname resolution in URLs.  If
        ``None``, a new resolver with default configuration is used (not the
        default resolver, to avoid a DoH chicken-and-egg problem).  Only
        effective when using httpx.
    :type resolver: :py:class:`dns.resolver.Resolver` or ``None``
    :param family: Address family.  ``socket.AF_UNSPEC`` (the default)
        retrieves both A and AAAA records.
    :type family: int
    :param http_version: Which HTTP version to use.
    :type http_version: :py:class:`dns.query.HTTPVersion`
    :rtype: :py:class:`dns.message.Message`
    """

    af, _, the_source = _destination_and_source(where, port, source, source_port, False)
    # we bind url and then override as pyright can't figure out all paths bind.
    url = where
    if af is not None and dns.inet.is_address(where):
        if af == socket.AF_INET:
            url = f"https://{where}:{port}{path}"
        elif af == socket.AF_INET6:
            url = f"https://[{where}]:{port}{path}"

    extensions = {}
    if bootstrap_address is None:
        # pylint: disable=possibly-used-before-assignment
        parsed = urllib.parse.urlparse(url)
        if parsed.hostname is None:
            raise ValueError("no hostname in URL")
        if dns.inet.is_address(parsed.hostname):
            bootstrap_address = parsed.hostname
            extensions["sni_hostname"] = parsed.hostname
        if parsed.port is not None:
            port = parsed.port

    if http_version == HTTPVersion.H3 or (
        http_version == HTTPVersion.DEFAULT and not have_doh
    ):
        if bootstrap_address is None:
            resolver = _maybe_get_resolver(resolver)
            assert parsed.hostname is not None  # pyright: ignore
            answers = resolver.resolve_name(parsed.hostname, family)  # pyright: ignore
            bootstrap_address = random.choice(list(answers.addresses()))
        if session and not isinstance(session, dns.quic.SyncQuicConnection):
            raise ValueError("session parameter must be a dns.quic.SyncQuicConnection.")
        return _http3(
            q,
            bootstrap_address,
            url,  # pyright: ignore
            timeout,
            port,
            source,
            source_port,
            one_rr_per_rrset,
            ignore_trailing,
            verify=verify,
            post=post,
            connection=session,
        )

    if not have_doh:
        raise NoDOH  # pragma: no cover
    if session and not isinstance(session, httpx.Client):  # pyright: ignore
        raise ValueError("session parameter must be an httpx.Client")

    wire = q.to_wire()
    headers = {"accept": "application/dns-message"}

    h1 = http_version in (HTTPVersion.H1, HTTPVersion.DEFAULT)
    h2 = http_version in (HTTPVersion.H2, HTTPVersion.DEFAULT)

    # set source port and source address

    if the_source is None:
        local_address = None
        local_port = 0
    else:
        local_address = the_source[0]
        local_port = the_source[1]

    if session:
        cm: contextlib.AbstractContextManager = contextlib.nullcontext(session)
    else:
        transport = _HTTPTransport(
            local_address=local_address,
            http1=h1,
            http2=h2,
            verify=verify,
            local_port=local_port,
            bootstrap_address=bootstrap_address,
            resolver=resolver,
            family=family,  # pyright: ignore
        )

        cm = httpx.Client(  # pyright: ignore
            http1=h1, http2=h2, verify=verify, transport=transport  # type: ignore
        )
    with cm as session:
        # see https://tools.ietf.org/html/rfc8484#section-4.1.1 for DoH
        # GET and POST examples
        assert session is not None
        if post:
            headers.update(
                {
                    "content-type": "application/dns-message",
                    "content-length": str(len(wire)),
                }
            )
            response = session.post(
                url,
                headers=headers,
                content=wire,
                timeout=timeout,
                extensions=extensions,
            )
        else:
            wire = base64.urlsafe_b64encode(wire).rstrip(b"=")
            twire = wire.decode()  # httpx does a repr() if we give it bytes
            response = session.get(
                url,
                headers=headers,
                timeout=timeout,
                params={"dns": twire},
                extensions=extensions,
            )

    # see https://tools.ietf.org/html/rfc8484#section-4.2.1 for info about DoH
    # status codes
    if response.status_code < 200 or response.status_code > 299:
        raise ValueError(
            f"{where} responded with status code {response.status_code}"
            f"\nResponse body: {response.content}"
        )
    r = dns.message.from_wire(
        response.content,
        keyring=q.keyring,
        request_mac=q.request_mac,
        one_rr_per_rrset=one_rr_per_rrset,
        ignore_trailing=ignore_trailing,
    )
    r.time = response.elapsed.total_seconds()
    if not q.is_response(r):
        raise BadResponse
    return r


def _find_header(headers: dns.quic.Headers, name: bytes) -> bytes:
    if headers is None:
        raise KeyError
    for header, value in headers:
        if header == name:
            return value
    raise KeyError


def _check_status(headers: dns.quic.Headers, peer: str, wire: bytes) -> None:
    value = _find_header(headers, b":status")
    if value is None:
        raise SyntaxError("no :status header in response")
    status = int(value)
    if status < 0:
        raise SyntaxError("status is negative")
    if status < 200 or status > 299:
        error = ""
        if len(wire) > 0:
            try:
                error = ": " + wire.decode()
            except Exception:
                pass
        raise ValueError(f"{peer} responded with status code {status}{error}")


def _http3(
    q: dns.message.Message,
    where: str,
    url: str,
    timeout: float | None = None,
    port: int = 443,
    source: str | None = None,
    source_port: int = 0,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    verify: bool | str | ssl.SSLContext = True,
    post: bool = True,
    connection: dns.quic.SyncQuicConnection | None = None,
) -> dns.message.Message:
    if not dns.quic.have_quic:
        raise NoDOH("DNS-over-HTTP3 is not available.")  # pragma: no cover

    url_parts = urllib.parse.urlparse(url)
    hostname = url_parts.hostname
    assert hostname is not None
    if url_parts.port is not None:
        port = url_parts.port

    q.id = 0
    wire = q.to_wire()
    the_connection: dns.quic.SyncQuicConnection
    the_manager: dns.quic.SyncQuicManager
    if connection:
        manager: contextlib.AbstractContextManager = contextlib.nullcontext(None)
    else:
        manager = dns.quic.SyncQuicManager(
            verify_mode=verify, server_name=hostname, h3=True  # pyright: ignore
        )
        the_manager = manager  # for type checking happiness

    with manager:
        if connection:
            the_connection = connection
        else:
            the_connection = the_manager.connect(  # pyright: ignore
                where, port, source, source_port
            )
        start, expiration = _compute_times(timeout)
        with the_connection.make_stream(timeout) as stream:  # type: ignore
            stream.send_h3(url, wire, post)
            wire = stream.receive(_remaining(expiration))
            _check_status(stream.headers(), where, wire)
        finish = time.time()
    r = dns.message.from_wire(
        wire,
        keyring=q.keyring,
        request_mac=q.request_mac,
        one_rr_per_rrset=one_rr_per_rrset,
        ignore_trailing=ignore_trailing,
    )
    r.time = max(finish - start, 0.0)
    if not q.is_response(r):
        raise BadResponse
    return r


def _udp_recv(sock, max_size, expiration):
    """Reads a datagram from the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    while True:
        try:
            return sock.recvfrom(max_size)
        except BlockingIOError:
            _wait_for_readable(sock, expiration)


def _udp_send(sock, data, destination, expiration):
    """Sends the specified datagram to destination over the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    while True:
        try:
            if destination:
                return sock.sendto(data, destination)
            else:
                return sock.send(data)
        except BlockingIOError:  # pragma: no cover
            _wait_for_writable(sock, expiration)


def send_udp(
    sock: Any,
    what: dns.message.Message | bytes,
    destination: Any,
    expiration: float | None = None,
) -> tuple[int, float]:
    """Send a DNS message to the specified UDP socket.

    :param sock: The socket to use.
    :type sock: socket
    :param what: The message to send.
    :type what: bytes or :py:class:`dns.message.Message`
    :param destination: A destination tuple appropriate for the address family
        of the socket.
    :param expiration: The absolute time at which to raise a timeout
        exception.  ``None`` means no timeout.
    :type expiration: float or ``None``
    :returns: A ``(bytes_sent, sent_time)`` tuple.
    :rtype: tuple[int, float]
    """

    if isinstance(what, dns.message.Message):
        what = what.to_wire()
    sent_time = time.time()
    n = _udp_send(sock, what, destination, expiration)
    return (n, sent_time)


def receive_udp(
    sock: Any,
    destination: Any | None = None,
    expiration: float | None = None,
    ignore_unexpected: bool = False,
    one_rr_per_rrset: bool = False,
    keyring: dict[dns.name.Name, dns.tsig.Key] | None = None,
    request_mac: bytes | None = b"",
    ignore_trailing: bool = False,
    raise_on_truncation: bool = False,
    ignore_errors: bool = False,
    query: dns.message.Message | None = None,
) -> Any:
    """Read a DNS message from a UDP socket.

    Raises if the message is malformed, if network errors occur, of if
    there is a timeout.

    :param sock: The socket to read from.
    :type sock: socket
    :param destination: Destination tuple indicating where the message is
        expected to arrive from (where the associated query was sent).
        ``None`` means accept from any source.
    :param expiration: The absolute time at which to raise a timeout
        exception.  ``None`` means no timeout.
    :type expiration: float or ``None``
    :param ignore_unexpected: If ``True``, ignore responses from unexpected
        sources.
    :type ignore_unexpected: bool
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param keyring: The keyring to use for TSIG.
    :type keyring: dict or ``None``
    :param request_mac: The MAC of the request (for TSIG).
    :type request_mac: bytes or ``None``
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :param raise_on_truncation: If ``True``, raise an exception if the TC
        bit is set.
    :type raise_on_truncation: bool
    :param ignore_errors: If ``True``, ignore format errors or response
        mismatches and keep listening for a valid response.
    :type ignore_errors: bool
    :param query: If not ``None`` and *ignore_errors* is ``True``, verify
        the received message is a response to this query.
    :type query: :py:class:`dns.message.Message` or ``None``
    :returns: If *destination* is not ``None``, a
        ``(message, received_time)`` tuple; otherwise a
        ``(message, received_time, from_address)`` tuple.
    :rtype: tuple
    """

    wire = b""
    while True:
        wire, from_address = _udp_recv(sock, 65535, expiration)
        if not _matches_destination(
            sock.family, from_address, destination, ignore_unexpected
        ):
            continue
        received_time = time.time()
        try:
            r = dns.message.from_wire(
                wire,
                keyring=keyring,
                request_mac=request_mac,
                one_rr_per_rrset=one_rr_per_rrset,
                ignore_trailing=ignore_trailing,
                raise_on_truncation=raise_on_truncation,
            )
        except dns.message.Truncated as e:
            # If we got Truncated and not FORMERR, we at least got the header with TC
            # set, and very likely the question section, so we'll re-raise if the
            # message seems to be a response as we need to know when truncation happens.
            # We need to check that it seems to be a response as we don't want a random
            # injected message with TC set to cause us to bail out.
            if (
                ignore_errors
                and query is not None
                and not query.is_response(e.message())
            ):
                continue
            else:
                raise
        except Exception:
            if ignore_errors:
                continue
            else:
                raise
        if ignore_errors and query is not None and not query.is_response(r):
            continue
        if destination:
            return (r, received_time)
        else:
            return (r, received_time, from_address)


def udp(
    q: dns.message.Message,
    where: str,
    timeout: float | None = None,
    port: int = 53,
    source: str | None = None,
    source_port: int = 0,
    ignore_unexpected: bool = False,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    raise_on_truncation: bool = False,
    sock: Any | None = None,
    ignore_errors: bool = False,
) -> dns.message.Message:
    """Return the response obtained after sending a query via UDP.

    :param q: The query to send.
    :type q: :py:class:`dns.message.Message`
    :param where: IPv4 or IPv6 address of the nameserver.
    :type where: str
    :param timeout: Seconds to wait before timing out.  ``None`` means wait
        forever.
    :type timeout: float or ``None``
    :param port: The port to send the message to.  Default is 53.
    :type port: int
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default
        is 0.
    :type source_port: int
    :param ignore_unexpected: If ``True``, ignore responses from unexpected
        sources.
    :type ignore_unexpected: bool
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :param raise_on_truncation: If ``True``, raise an exception if the TC
        bit is set.
    :type raise_on_truncation: bool
    :param sock: The socket to use.  If ``None`` (the default), a socket is
        created.  If provided, must be a nonblocking datagram socket; *source*
        and *source_port* are ignored.
    :type sock: ``socket.socket`` or ``None``
    :param ignore_errors: If ``True``, ignore format errors or response
        mismatches and keep listening for a valid response.
    :type ignore_errors: bool
    :rtype: :py:class:`dns.message.Message`
    """

    wire = q.to_wire()
    af, destination, source = _destination_and_source(
        where, port, source, source_port, True
    )
    begin_time, expiration = _compute_times(timeout)
    if sock:
        cm: contextlib.AbstractContextManager = contextlib.nullcontext(sock)
    else:
        assert af is not None
        cm = make_socket(af, socket.SOCK_DGRAM, source)
    with cm as s:
        send_udp(s, wire, destination, expiration)
        r, received_time = receive_udp(
            s,
            destination,
            expiration,
            ignore_unexpected,
            one_rr_per_rrset,
            q.keyring,
            q.mac,
            ignore_trailing,
            raise_on_truncation,
            ignore_errors,
            q,
        )
        r.time = received_time - begin_time
        # We don't need to check q.is_response() if we are in ignore_errors mode
        # as receive_udp() will have checked it.
        if not (ignore_errors or q.is_response(r)):
            raise BadResponse
        return r
    assert (
        False  # help mypy figure out we can't get here  lgtm[py/unreachable-statement]
    )


def udp_with_fallback(
    q: dns.message.Message,
    where: str,
    timeout: float | None = None,
    port: int = 53,
    source: str | None = None,
    source_port: int = 0,
    ignore_unexpected: bool = False,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    udp_sock: Any | None = None,
    tcp_sock: Any | None = None,
    ignore_errors: bool = False,
) -> tuple[dns.message.Message, bool]:
    """Return the response to the query, trying UDP first and falling back
    to TCP if UDP results in a truncated response.

    :param q: The query to send.
    :type q: :py:class:`dns.message.Message`
    :param where: IPv4 or IPv6 address of the nameserver.
    :type where: str
    :param timeout: Seconds to wait before timing out.  ``None`` means wait
        forever.
    :type timeout: float or ``None``
    :param port: The port to send the message to.  Default is 53.
    :type port: int
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default
        is 0.
    :type source_port: int
    :param ignore_unexpected: If ``True``, ignore responses from unexpected
        sources.
    :type ignore_unexpected: bool
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :param udp_sock: The socket to use for the UDP query.  If ``None``
        (the default), a socket is created.  If provided, must be a
        nonblocking datagram socket; *source* and *source_port* are ignored.
    :type udp_sock: ``socket.socket`` or ``None``
    :param tcp_sock: The connected socket to use for the TCP query.  If
        ``None`` (the default), a socket is created.  If provided, must be a
        nonblocking connected stream socket; *where*, *source* and
        *source_port* are ignored.
    :type tcp_sock: ``socket.socket`` or ``None``
    :param ignore_errors: If ``True``, ignore UDP format errors or response
        mismatches and keep listening for a valid response.
    :type ignore_errors: bool
    :returns: A ``(message, used_tcp)`` tuple; *used_tcp* is ``True`` if and
        only if TCP was used.
    :rtype: tuple[:py:class:`dns.message.Message`, bool]
    """
    try:
        response = udp(
            q,
            where,
            timeout,
            port,
            source,
            source_port,
            ignore_unexpected,
            one_rr_per_rrset,
            ignore_trailing,
            True,
            udp_sock,
            ignore_errors,
        )
        return (response, False)
    except dns.message.Truncated:
        response = tcp(
            q,
            where,
            timeout,
            port,
            source,
            source_port,
            one_rr_per_rrset,
            ignore_trailing,
            tcp_sock,
        )
        return (response, True)


def _net_read(sock, count, expiration):
    """Read the specified number of bytes from sock.  Keep trying until we
    either get the desired amount, or we hit EOF.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    s = b""
    while count > 0:
        try:
            n = sock.recv(count)
            if n == b"":
                raise EOFError("EOF")
            count -= len(n)
            s += n
        except (BlockingIOError, ssl.SSLWantReadError):
            _wait_for_readable(sock, expiration)
        except ssl.SSLWantWriteError:  # pragma: no cover
            _wait_for_writable(sock, expiration)
    return s


def _net_write(sock, data, expiration):
    """Write the specified data to the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    current = 0
    l = len(data)
    while current < l:
        try:
            current += sock.send(data[current:])
        except (BlockingIOError, ssl.SSLWantWriteError):
            _wait_for_writable(sock, expiration)
        except ssl.SSLWantReadError:  # pragma: no cover
            _wait_for_readable(sock, expiration)


def send_tcp(
    sock: Any,
    what: dns.message.Message | bytes,
    expiration: float | None = None,
) -> tuple[int, float]:
    """Send a DNS message to the specified TCP socket.

    :param sock: The socket to use.
    :type sock: socket
    :param what: The message to send.
    :type what: bytes or :py:class:`dns.message.Message`
    :param expiration: The absolute time at which to raise a timeout
        exception.  ``None`` means no timeout.
    :type expiration: float or ``None``
    :returns: A ``(bytes_sent, sent_time)`` tuple.
    :rtype: tuple[int, float]
    """

    if isinstance(what, dns.message.Message):
        tcpmsg = what.to_wire(prepend_length=True)
    else:
        # copying the wire into tcpmsg is inefficient, but lets us
        # avoid writev() or doing a short write that would get pushed
        # onto the net
        tcpmsg = len(what).to_bytes(2, "big") + what
    sent_time = time.time()
    _net_write(sock, tcpmsg, expiration)
    return (len(tcpmsg), sent_time)


def receive_tcp(
    sock: Any,
    expiration: float | None = None,
    one_rr_per_rrset: bool = False,
    keyring: dict[dns.name.Name, dns.tsig.Key] | None = None,
    request_mac: bytes | None = b"",
    ignore_trailing: bool = False,
) -> tuple[dns.message.Message, float]:
    """Read a DNS message from a TCP socket.

    :param sock: The socket to read from.
    :type sock: socket
    :param expiration: The absolute time at which to raise a timeout
        exception.  ``None`` means no timeout.
    :type expiration: float or ``None``
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param keyring: The keyring to use for TSIG.
    :type keyring: dict or ``None``
    :param request_mac: The MAC of the request (for TSIG).
    :type request_mac: bytes or ``None``
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :returns: A ``(message, received_time)`` tuple.
    :rtype: tuple[:py:class:`dns.message.Message`, float]
    """

    ldata = _net_read(sock, 2, expiration)
    (l,) = struct.unpack("!H", ldata)
    wire = _net_read(sock, l, expiration)
    received_time = time.time()
    r = dns.message.from_wire(
        wire,
        keyring=keyring,
        request_mac=request_mac,
        one_rr_per_rrset=one_rr_per_rrset,
        ignore_trailing=ignore_trailing,
    )
    return (r, received_time)


def _connect(s, address, expiration):
    err = s.connect_ex(address)
    if err == 0:
        return
    if err in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
        _wait_for_writable(s, expiration)
        err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    if err != 0:
        raise OSError(err, os.strerror(err))


def tcp(
    q: dns.message.Message,
    where: str,
    timeout: float | None = None,
    port: int = 53,
    source: str | None = None,
    source_port: int = 0,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    sock: Any | None = None,
) -> dns.message.Message:
    """Return the response obtained after sending a query via TCP.

    :param q: The query to send.
    :type q: :py:class:`dns.message.Message`
    :param where: IPv4 or IPv6 address of the nameserver.
    :type where: str
    :param timeout: Seconds to wait before timing out.  ``None`` means wait
        forever.
    :type timeout: float or ``None``
    :param port: The port to send the message to.  Default is 53.
    :type port: int
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default
        is 0.
    :type source_port: int
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :param sock: The connected socket to use.  If ``None`` (the default), a
        socket is created.  If provided, must be a nonblocking connected
        stream socket; *where*, *port*, *source* and *source_port* are
        ignored.
    :type sock: ``socket.socket`` or ``None``
    :rtype: :py:class:`dns.message.Message`
    """

    wire = q.to_wire()
    begin_time, expiration = _compute_times(timeout)
    if sock:
        cm: contextlib.AbstractContextManager = contextlib.nullcontext(sock)
    else:
        af, destination, source = _destination_and_source(
            where, port, source, source_port, True
        )
        assert af is not None
        cm = make_socket(af, socket.SOCK_STREAM, source)
    with cm as s:
        if not sock:
            # pylint: disable=possibly-used-before-assignment
            _connect(s, destination, expiration)  # pyright: ignore
        send_tcp(s, wire, expiration)
        r, received_time = receive_tcp(
            s, expiration, one_rr_per_rrset, q.keyring, q.mac, ignore_trailing
        )
        r.time = received_time - begin_time
        if not q.is_response(r):
            raise BadResponse
        return r
    assert (
        False  # help mypy figure out we can't get here  lgtm[py/unreachable-statement]
    )


def _tls_handshake(s, expiration):
    while True:
        try:
            s.do_handshake()
            return
        except ssl.SSLWantReadError:
            _wait_for_readable(s, expiration)
        except ssl.SSLWantWriteError:  # pragma: no cover
            _wait_for_writable(s, expiration)


def make_ssl_context(
    verify: bool | str = True,
    check_hostname: bool = True,
    alpns: list[str] | None = None,
) -> ssl.SSLContext:
    """Make an SSL context

    If *verify* is ``True``, the default, then certificate verification will occur using
    the standard CA roots.  If *verify* is ``False``, then certificate verification will
    be disabled.  If *verify* is a string which is a valid pathname, then if the
    pathname is a regular file, the CA roots will be taken from the file, otherwise if
    the pathname is a directory roots will be taken from the directory.

    If *check_hostname* is ``True``, the default, then the hostname of the server must
    be specified when connecting and the server's certificate must authorize the
    hostname.  If ``False``, then hostname checking is disabled.

    *aplns* is ``None`` or a list of TLS ALPN (Application Layer Protocol Negotiation)
    strings to use in negotiation.  For DNS-over-TLS, the right value is `["dot"]`.
    """
    cafile, capath = dns._tls_util.convert_verify_to_cafile_and_capath(verify)
    ssl_context = ssl.create_default_context(cafile=cafile, capath=capath)
    # the pyright ignores below are because it gets confused between the
    # _no_ssl compatibility types and the real ones.
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2  # type: ignore
    ssl_context.check_hostname = check_hostname
    if verify is False:
        ssl_context.verify_mode = ssl.CERT_NONE  # type: ignore
    if alpns is not None:
        ssl_context.set_alpn_protocols(alpns)
    return ssl_context  # pyright: ignore


# for backwards compatibility
def _make_dot_ssl_context(
    server_hostname: str | None, verify: bool | str
) -> ssl.SSLContext:
    return make_ssl_context(verify, server_hostname is not None, ["dot"])


def tls(
    q: dns.message.Message,
    where: str,
    timeout: float | None = None,
    port: int = 853,
    source: str | None = None,
    source_port: int = 0,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    sock: ssl.SSLSocket | None = None,
    ssl_context: ssl.SSLContext | None = None,
    server_hostname: str | None = None,
    verify: bool | str = True,
) -> dns.message.Message:
    """Return the response obtained after sending a query via TLS.

    :param q: The query to send.
    :type q: :py:class:`dns.message.Message`
    :param where: IPv4 or IPv6 address of the nameserver.
    :type where: str
    :param timeout: Seconds to wait before timing out.  ``None`` means wait
        forever.
    :type timeout: float or ``None``
    :param port: The port to send the message to.  Default is 853.
    :type port: int
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default
        is 0.
    :type source_port: int
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :param sock: The SSL socket to use.  If ``None`` (the default), a socket
        is created.  If provided, must be a nonblocking connected SSL stream
        socket; *where*, *port*, *source*, *source_port*, and *ssl_context*
        are ignored.
    :type sock: ``ssl.SSLSocket`` or ``None``
    :param ssl_context: The SSL context to use when establishing the TLS
        connection.  If ``None`` (the default), one is created with the
        default configuration.
    :type ssl_context: ``ssl.SSLContext`` or ``None``
    :param server_hostname: The server's hostname, or ``None``.  If ``None``
        and an SSL context is created, hostname checking is disabled.
    :type server_hostname: str or ``None``
    :param verify: If ``True``, verify the TLS certificate using default CA
        roots; if ``False``, disable verification; if a ``str``, path to a
        certificate file or directory.
    :type verify: bool or str
    :rtype: :py:class:`dns.message.Message`
    """

    if sock:
        #
        # If a socket was provided, there's no special TLS handling needed.
        #
        return tcp(
            q,
            where,
            timeout,
            port,
            source,
            source_port,
            one_rr_per_rrset,
            ignore_trailing,
            sock,
        )

    wire = q.to_wire()
    begin_time, expiration = _compute_times(timeout)
    af, destination, source = _destination_and_source(
        where, port, source, source_port, True
    )
    assert af is not None  # where must be an address
    if ssl_context is None:
        ssl_context = make_ssl_context(verify, server_hostname is not None, ["dot"])

    with make_ssl_socket(
        af,
        socket.SOCK_STREAM,
        ssl_context=ssl_context,
        server_hostname=server_hostname,
        source=source,
    ) as s:
        _connect(s, destination, expiration)
        _tls_handshake(s, expiration)
        send_tcp(s, wire, expiration)
        r, received_time = receive_tcp(
            s, expiration, one_rr_per_rrset, q.keyring, q.mac, ignore_trailing
        )
        r.time = received_time - begin_time
        if not q.is_response(r):
            raise BadResponse
        return r
    assert (
        False  # help mypy figure out we can't get here  lgtm[py/unreachable-statement]
    )


def quic(
    q: dns.message.Message,
    where: str,
    timeout: float | None = None,
    port: int = 853,
    source: str | None = None,
    source_port: int = 0,
    one_rr_per_rrset: bool = False,
    ignore_trailing: bool = False,
    connection: dns.quic.SyncQuicConnection | None = None,
    verify: bool | str = True,
    hostname: str | None = None,
    server_hostname: str | None = None,
) -> dns.message.Message:
    """Return the response obtained after sending a query via DNS-over-QUIC.

    :param q: The query to send.
    :type q: :py:class:`dns.message.Message`
    :param where: The nameserver IP address.
    :type where: str
    :param timeout: Seconds to wait before timing out.  ``None`` means wait
        forever.
    :type timeout: float or ``None``
    :param port: The port to send the query to.  Default is 853.
    :type port: int
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default
        is 0.
    :type source_port: int
    :param one_rr_per_rrset: If ``True``, put each RR into its own RRset.
    :type one_rr_per_rrset: bool
    :param ignore_trailing: If ``True``, ignore trailing junk at end of the
        received message.
    :type ignore_trailing: bool
    :param connection: If provided, the QUIC connection to use.
    :type connection: :py:class:`dns.quic.SyncQuicConnection` or ``None``
    :param verify: If ``True``, verify the TLS certificate using default CA
        roots; if ``False``, disable verification; if a ``str``, path to a
        certificate file or directory.
    :type verify: bool or str
    :param hostname: The server's hostname, or ``None``.  If ``None`` and an
        SSL context is created, hostname checking is disabled.
    :type hostname: str or ``None``
    :param server_hostname: Deprecated alias for *hostname*.
    :type server_hostname: str or ``None``
    :rtype: :py:class:`dns.message.Message`
    """

    if not dns.quic.have_quic:
        raise NoDOQ("DNS-over-QUIC is not available.")  # pragma: no cover

    if server_hostname is not None and hostname is None:
        hostname = server_hostname

    q.id = 0
    wire = q.to_wire()
    the_connection: dns.quic.SyncQuicConnection
    the_manager: dns.quic.SyncQuicManager
    if connection:
        manager: contextlib.AbstractContextManager = contextlib.nullcontext(None)
        the_connection = connection
    else:
        manager = dns.quic.SyncQuicManager(
            verify_mode=verify, server_name=hostname  # pyright: ignore
        )
        the_manager = manager  # for type checking happiness

    with manager:
        if not connection:
            the_connection = the_manager.connect(  # pyright: ignore
                where, port, source, source_port
            )
        start, expiration = _compute_times(timeout)
        with the_connection.make_stream(timeout) as stream:  # type: ignore
            stream.send(wire, True)
            wire = stream.receive(_remaining(expiration))
        finish = time.time()
    r = dns.message.from_wire(
        wire,
        keyring=q.keyring,
        request_mac=q.request_mac,
        one_rr_per_rrset=one_rr_per_rrset,
        ignore_trailing=ignore_trailing,
    )
    r.time = max(finish - start, 0.0)
    if not q.is_response(r):
        raise BadResponse
    return r


class UDPMode(enum.IntEnum):
    """How should UDP be used in an IXFR from :py:func:`inbound_xfr()`?

    NEVER means "never use UDP; always use TCP"
    TRY_FIRST means "try to use UDP but fall back to TCP if needed"
    ONLY means "raise ``dns.xfr.UseTCP`` if trying UDP does not succeed"
    """

    NEVER = 0
    TRY_FIRST = 1
    ONLY = 2


def _inbound_xfr(
    txn_manager: dns.transaction.TransactionManager,
    s: socket.socket | ssl.SSLSocket,
    query: dns.message.Message,
    serial: int | None,
    timeout: float | None,
    expiration: float | None,
) -> Any:
    """Given a socket, does the zone transfer."""
    rdtype = query.question[0].rdtype
    is_ixfr = rdtype == dns.rdatatype.IXFR
    origin = txn_manager.from_wire_origin()
    wire = query.to_wire()
    is_udp = isinstance(s, socket.socket) and s.type == socket.SOCK_DGRAM
    if is_udp:
        _udp_send(s, wire, None, expiration)
    else:
        tcpmsg = struct.pack("!H", len(wire)) + wire
        _net_write(s, tcpmsg, expiration)
    with dns.xfr.Inbound(txn_manager, rdtype, serial, is_udp) as inbound:
        done = False
        tsig_ctx = None
        r: dns.message.Message | None = None
        while not done:
            _, mexpiration = _compute_times(timeout)
            if mexpiration is None or (
                expiration is not None and mexpiration > expiration
            ):
                mexpiration = expiration
            if is_udp:
                rwire, _ = _udp_recv(s, 65535, mexpiration)
            else:
                ldata = _net_read(s, 2, mexpiration)
                (l,) = struct.unpack("!H", ldata)
                rwire = _net_read(s, l, mexpiration)
            r = dns.message.from_wire(
                rwire,
                keyring=query.keyring,
                request_mac=query.mac,
                xfr=True,
                origin=origin,
                tsig_ctx=tsig_ctx,
                multi=(not is_udp),
                one_rr_per_rrset=is_ixfr,
            )
            done = inbound.process_message(r)
            yield r
            tsig_ctx = r.tsig_ctx
        if query.keyring and r is not None and not r.had_tsig:
            raise dns.exception.FormError("missing TSIG")


def xfr(
    where: str,
    zone: dns.name.Name | str,
    rdtype: dns.rdatatype.RdataType | str = dns.rdatatype.AXFR,
    rdclass: dns.rdataclass.RdataClass | str = dns.rdataclass.IN,
    timeout: float | None = None,
    port: int = 53,
    keyring: dict[dns.name.Name, dns.tsig.Key] | None = None,
    keyname: dns.name.Name | str | None = None,
    relativize: bool = True,
    lifetime: float | None = None,
    source: str | None = None,
    source_port: int = 0,
    serial: int = 0,
    use_udp: bool = False,
    keyalgorithm: dns.name.Name | str = dns.tsig.default_algorithm,
) -> Any:
    """Return a generator for the responses to a zone transfer.

    :param where: IPv4 or IPv6 address of the nameserver.
    :type where: str
    :param zone: The name of the zone to transfer.
    :type zone: :py:class:`dns.name.Name` or str
    :param rdtype: The type of zone transfer.  Default is
        ``dns.rdatatype.AXFR``; use ``dns.rdatatype.IXFR`` for incremental.
    :type rdtype: :py:class:`dns.rdatatype.RdataType` or str or int
    :param rdclass: The class of the zone transfer.  Default is
        ``dns.rdataclass.IN``.
    :type rdclass: :py:class:`dns.rdataclass.RdataClass` or str or int
    :param timeout: Seconds to wait for each response message.  ``None``
        means wait forever.
    :type timeout: float or ``None``
    :param port: The port to send the message to.  Default is 53.
    :type port: int
    :param keyring: The keyring to use for TSIG.
    :type keyring: dict or ``None``
    :param keyname: The name of the TSIG key to use.
    :type keyname: :py:class:`dns.name.Name` or str or ``None``
    :param relativize: If ``True``, relativize all names to the zone origin.
        Must match the setting passed to ``dns.zone.from_xfr()``.
    :type relativize: bool
    :param lifetime: Total seconds to spend on the transfer.  ``None`` means
        no limit.
    :type lifetime: float or ``None``
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default
        is 0.
    :type source_port: int
    :param serial: SOA serial number to use as the IXFR base (only
        meaningful when *rdtype* is ``dns.rdatatype.IXFR``).
    :type serial: int
    :param use_udp: If ``True``, use UDP (only meaningful for IXFR).
    :type use_udp: bool
    :param keyalgorithm: The TSIG algorithm to use.
    :type keyalgorithm: :py:class:`dns.name.Name` or str
    :returns: A generator of :py:class:`dns.message.Message` objects.
    """

    class DummyTransactionManager(dns.transaction.TransactionManager):
        def __init__(self, origin, relativize):
            self.info = (origin, relativize, dns.name.empty if relativize else origin)

        def origin_information(self):
            return self.info

        def get_class(self) -> dns.rdataclass.RdataClass:
            raise NotImplementedError  # pragma: no cover

        def reader(self):
            raise NotImplementedError  # pragma: no cover

        def writer(self, replacement: bool = False) -> dns.transaction.Transaction:
            class DummyTransaction:
                def nop(self, *args, **kw):
                    pass

                def __getattr__(self, _):
                    return self.nop

            return cast(dns.transaction.Transaction, DummyTransaction())

    if isinstance(zone, str):
        zone = dns.name.from_text(zone)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    q = dns.message.make_query(zone, rdtype, rdclass)
    if rdtype == dns.rdatatype.IXFR:
        rrset = q.find_rrset(
            q.authority, zone, dns.rdataclass.IN, dns.rdatatype.SOA, create=True
        )
        soa = dns.rdata.from_text("IN", "SOA", f". . {serial} 0 0 0 0")
        rrset.add(soa, 0)
    if keyring is not None:
        q.use_tsig(keyring, keyname, algorithm=keyalgorithm)
    af, destination, source = _destination_and_source(
        where, port, source, source_port, True
    )
    assert af is not None
    _, expiration = _compute_times(lifetime)
    tm = DummyTransactionManager(zone, relativize)
    if use_udp and rdtype != dns.rdatatype.IXFR:
        raise ValueError("cannot do a UDP AXFR")
    sock_type = socket.SOCK_DGRAM if use_udp else socket.SOCK_STREAM
    with make_socket(af, sock_type, source) as s:
        _connect(s, destination, expiration)
        yield from _inbound_xfr(tm, s, q, serial, timeout, expiration)


def inbound_xfr(
    where: str,
    txn_manager: dns.transaction.TransactionManager,
    query: dns.message.Message | None = None,
    port: int = 53,
    timeout: float | None = None,
    lifetime: float | None = None,
    source: str | None = None,
    source_port: int = 0,
    udp_mode: UDPMode = UDPMode.NEVER,
) -> None:
    """Conduct an inbound transfer and apply it via a transaction from the
    txn_manager.

    :param where: IPv4 or IPv6 address of the nameserver.
    :type where: str
    :param txn_manager: The transaction manager for this transfer (typically
        a :py:class:`dns.zone.Zone`).
    :type txn_manager: :py:class:`dns.transaction.TransactionManager`
    :param query: The query to send.  If not supplied, a default query is
        constructed from *txn_manager*.
    :param port: The port to send the message to.  Default is 53.
    :type port: int
    :param timeout: Seconds to wait for each response message.  ``None``
        means wait forever.
    :type timeout: float or ``None``
    :param lifetime: Total seconds to spend on the transfer.  ``None`` means
        no limit.
    :type lifetime: float or ``None``
    :param source: Source IPv4 or IPv6 address.  Default is the wildcard
        address.
    :type source: str or ``None``
    :param source_port: The port from which to send the message.  Default
        is 0.
    :type source_port: int
    :param udp_mode: How to use UDP for IXFRs.  Default is
        ``dns.query.UDPMode.NEVER`` (TCP only).  ``TRY_FIRST`` tries UDP
        with TCP fallback; ``ONLY`` raises :py:exc:`dns.xfr.UseTCP` if UDP
        does not succeed.
    :type udp_mode: :py:class:`dns.query.UDPMode`
    """
    if query is None:
        query, serial = dns.xfr.make_query(txn_manager)
    else:
        serial = dns.xfr.extract_serial_from_query(query)

    af, destination, source = _destination_and_source(
        where, port, source, source_port, True
    )
    assert af is not None
    _, expiration = _compute_times(lifetime)
    if query.question[0].rdtype == dns.rdatatype.IXFR and udp_mode != UDPMode.NEVER:
        with make_socket(af, socket.SOCK_DGRAM, source) as s:
            _connect(s, destination, expiration)
            try:
                for _ in _inbound_xfr(
                    txn_manager, s, query, serial, timeout, expiration
                ):
                    pass
                return
            except dns.xfr.UseTCP:
                if udp_mode == UDPMode.ONLY:
                    raise

    with make_socket(af, socket.SOCK_STREAM, source) as s:
        _connect(s, destination, expiration)
        for _ in _inbound_xfr(txn_manager, s, query, serial, timeout, expiration):
            pass
