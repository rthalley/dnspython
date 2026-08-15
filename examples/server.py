"""An example asynchronous DNS server framework.

This module implements a small DNS server framework on top of anyio,
supporting UDP, TCP, and TLS transports.  Subclass :py:class:`DNSServer`
and implement its :py:meth:`DNSServer.query` method to build a server;
see :py:class:`ExampleDNSServer` for a minimal implementation.
"""

import argparse
import functools
import logging
import ssl
import struct
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Self

import anyio
import trustme
from anyio.abc import SocketAttribute, SocketStream, UDPSocket
from anyio.streams.buffered import BufferedByteReceiveStream
from anyio.streams.tls import TLSListener, TLSStream

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

DEFAULT_QUERY_TIMEOUT: Final[float] = 10.0
DEFAULT_RESPONSE_TIMEOUT: Final[float] = 10.0


class DNSTransport(StrEnum):
    """The transport protocol over which a DNS message was received."""

    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"


@dataclass(frozen=True)
class DNSClientContext:
    """Connection metadata for a DNS client.

    Instances describe the transport and the remote and local addresses
    of a client whose query is being processed, allowing query handlers
    to make policy decisions based on where a query came from.
    """

    transport: DNSTransport
    remote_address: str
    remote_port: int
    local_address: str | None = None
    local_port: int | None = None

    @classmethod
    def from_udp_socket(
        cls,
        udp_socket: UDPSocket,
        remote_address: str,
        remote_port: int,
    ) -> Self:
        """Create a DNSClientContext for a datagram received on a UDP socket.

        :param udp_socket: The socket on which the datagram was received;
            used to determine the local address and port.
        :type udp_socket: :py:class:`anyio.abc.UDPSocket`
        :param remote_address: The address the datagram was sent from.
        :type remote_address: str
        :param remote_port: The port the datagram was sent from.
        :type remote_port: int
        :returns: A context with the transport set to
            :py:attr:`DNSTransport.UDP`.
        :rtype: :py:class:`DNSClientContext`
        """

        local_address, local_port = udp_socket.extra(SocketAttribute.local_address)  # type: ignore

        return cls(
            transport=DNSTransport.UDP,
            remote_address=remote_address,
            remote_port=remote_port,
            local_address=str(local_address),
            local_port=int(local_port),
        )

    @classmethod
    def from_socket_stream(cls, socket_stream: SocketStream) -> Self:
        """Create a DNSClientContext for a stream connection.

        The remote and local addresses are taken from the stream's socket
        attributes.

        :param socket_stream: The stream over which the client is connected.
        :type socket_stream: :py:class:`anyio.abc.SocketStream`
        :returns: A context with the transport set to
            :py:attr:`DNSTransport.TLS` if *socket_stream* is a TLS stream,
            and :py:attr:`DNSTransport.TCP` otherwise.
        :rtype: :py:class:`DNSClientContext`
        """

        remote_address, remote_port = socket_stream.extra(
            SocketAttribute.remote_address
        )  # type: ignore
        local_address, local_port = socket_stream.extra(SocketAttribute.local_address)  # type: ignore

        return cls(
            transport=(
                DNSTransport.TLS
                if isinstance(socket_stream, TLSStream)
                else DNSTransport.TCP
            ),
            remote_address=str(remote_address),
            remote_port=int(remote_port),
            local_address=str(local_address),
            local_port=int(local_port),
        )


class DNSServer(ABC):
    """An abstract asynchronous DNS server.

    The server listens for DNS queries over UDP, TCP, and TLS, decodes
    them, and dispatches them to the :py:meth:`query` method, which
    subclasses must implement to provide the actual query processing
    logic.
    """

    def __init__(
        self,
        query_timeout: float = DEFAULT_QUERY_TIMEOUT,
        response_timeout: float = DEFAULT_RESPONSE_TIMEOUT,
    ) -> None:
        """Initialize the DNS server.

        :param query_timeout: The number of seconds to wait for a complete
            query to arrive on a stream connection.
        :type query_timeout: float
        :param response_timeout: The number of seconds allowed for
            processing a query and sending its responses.
        :type response_timeout: float
        """

        self.logger = logging.getLogger(__name__).getChild(self.__class__.__name__)
        self.query_timeout = query_timeout
        self.response_timeout = response_timeout

    async def run(
        self,
        host: str | None = None,
        listen_udp: bool | int = True,
        listen_tcp: bool | int = True,
        listen_tls: bool | int = False,
        certfile: str | None = None,
        keyfile: str | None = None,
        hostname: str | None = None,
    ) -> None:
        """Run the DNS server, starting listeners for the enabled transports.

        This method runs until cancelled.

        :param host: The address to listen on.  If ``None``, listen on all
            IPv4 and IPv6 addresses.
        :type host: str or ``None``
        :param listen_udp: Whether to listen for UDP queries.  ``True``
            listens on port 53; an ``int`` listens on that port; ``False``
            disables UDP.
        :type listen_udp: bool or int
        :param listen_tcp: Whether to listen for TCP queries.  ``True``
            listens on port 53; an ``int`` listens on that port; ``False``
            disables TCP
        :type listen_tcp: bool or int
        :param listen_tls: Whether to listen for TLS queries.  ``True``
            listens on port 853; an ``int`` listens on that port; ``False``
            disables TLS.
        :type listen_tls: bool or int
        :param certfile: The path to the TLS certificate chain file.  If
            ``None``, a self-signed certificate is generated.
        :type certfile: str or ``None``
        :param keyfile: The path to the TLS private key file.  If ``None``,
            the key is taken from *certfile*.
        :type keyfile: str or ``None``
        :param hostname: The hostname to use for the self-signed
            certificate; defaults to ``"localhost"``.  Ignored if
            *certfile* is given.
        :type hostname: str or ``None``
        """

        async with anyio.create_task_group() as tg:
            if listen_udp:
                udp_port = 53 if listen_udp is True else listen_udp
                if host:
                    tg.start_soon(
                        functools.partial(
                            self.udp_server,
                            host=host,
                            port=udp_port,
                        )
                    )
                else:
                    # Listen to both all IPv4 and IPv6 addresses if no specific host is provided
                    tg.start_soon(
                        functools.partial(
                            self.udp_server,
                            host="0.0.0.0",
                            port=udp_port,
                        )
                    )
                    tg.start_soon(
                        functools.partial(
                            self.udp_server,
                            host="::",
                            port=udp_port,
                        )
                    )
            if listen_tcp:
                tg.start_soon(
                    functools.partial(
                        self.tcp_server,
                        host=host,
                        port=53 if listen_tcp is True else listen_tcp,
                    )
                )
            if listen_tls:
                tg.start_soon(
                    functools.partial(
                        self.tls_server,
                        host=host,
                        port=853 if listen_tls is True else listen_tls,
                        hostname=hostname,
                        certfile=certfile,
                        keyfile=keyfile,
                    )
                )

    async def udp_server(
        self,
        host: str,
        port: int = 53,
    ) -> None:
        """Listen for DNS queries over UDP.

        Each received packet is handed off to
        :py:meth:`handle_udp_client` in its own task.  This method runs
        until cancelled.

        :param host: The local address to bind to.
        :type host: str
        :param port: The local port to bind to.
        :type port: int
        """

        self.logger.info("DNS UDP server listening to %s:%d", host or "*", port)

        async with (
            await anyio.create_udp_socket(
                local_host=host,
                local_port=port,
            ) as udp_socket,
            anyio.create_task_group() as tg,
        ):
            async for packet, (remote_address, remote_port) in udp_socket:
                client_context = DNSClientContext.from_udp_socket(
                    udp_socket, remote_address, remote_port
                )
                tg.start_soon(
                    self.handle_udp_client, udp_socket, packet, client_context
                )

    async def tcp_server(
        self,
        host: str | None = None,
        port: int = 53,
    ) -> None:
        """Listen for DNS queries over TCP.

        Each accepted connection is served by
        :py:meth:`handle_socket_stream_client`.  This method runs until cancelled.

        :param host: The local address to bind to.  If ``None``, listen on
            all addresses.
        :type host: str or ``None``
        :param port: The local port to bind to.
        :type port: int
        """

        self.logger.info("DNS TCP server listening to %s:%d", host or "*", port)

        tcp_listener = await anyio.create_tcp_listener(local_host=host, local_port=port)

        await tcp_listener.serve(self.handle_socket_stream_client)

    async def tls_server(
        self,
        host: str | None = None,
        port: int = 853,
        certfile: str | None = None,
        keyfile: str | None = None,
        hostname: str | None = None,
    ) -> None:
        """Listen for DNS queries over TLS (DNS-over-TLS).

        Each accepted connection is served by
        :py:meth:`handle_socket_stream_client`.  This method runs until cancelled.

        :param host: The local address to bind to.  If ``None``, listen on
            all addresses.
        :type host: str or ``None``
        :param port: The local port to bind to.
        :type port: int
        :param certfile: The path to the TLS certificate chain file.  If
            ``None``, a self-signed certificate for *hostname* is generated
            using trustme.
        :type certfile: str or ``None``
        :param keyfile: The path to the TLS private key file.  If ``None``,
            the key is taken from *certfile*.
        :type keyfile: str or ``None``
        :param hostname: The hostname to use for the self-signed
            certificate; defaults to ``"localhost"``.  Ignored if
            *certfile* is given.
        :type hostname: str or ``None``
        """

        self.logger.info("DNS TLS server listening to %s:%d", host or "*", port)

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        if certfile:
            context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        else:
            # Create a self-signed certificate for localhost using trustme
            trustme.CA().issue_cert(hostname or "localhost").configure_cert(context)

        tls_listener = TLSListener(
            await anyio.create_tcp_listener(local_host=host, local_port=port),
            context,
        )

        await tls_listener.serve(self.handle_socket_stream_client)

    async def handle_udp_client(
        self,
        udp_socket: UDPSocket,
        packet: bytes,
        client_context: DNSClientContext,
    ) -> None:
        """Process a DNS query received over UDP and send any responses.

        The packet is parsed into a query and dispatched to
        :py:meth:`handle_query`; any responses are sent back to the
        client, truncated if they exceed the client's advertised EDNS
        payload size (or the 512 byte default).  Packets that cannot be
        parsed are silently ignored.

        :param udp_socket: The socket on which the packet was received and
            on which responses will be sent.
        :type udp_socket: :py:class:`anyio.abc.UDPSocket`
        :param packet: The DNS query in wire format.
        :type packet: bytes
        :param client_context: The context of the client that sent the
            query.
        :type client_context: :py:class:`DNSClientContext`
        """

        self.logger.debug(
            "UDP packet from %s:%d",
            client_context.remote_address,
            client_context.remote_port,
        )

        try:
            with anyio.fail_after(self.response_timeout):
                try:
                    query = dns.message.from_wire(packet)
                except dns.exception.DNSException:
                    return

                if responses := await self.handle_query(
                    query=query,
                    client_context=client_context,
                ):
                    multi = len(responses) > 1
                    self.logger.debug("Returning %d DNS messages", len(responses))
                    # Truncate responses that exceed the client's advertised EDNS
                    # payload size (or the 512 byte default), setting the TC flag
                    max_size = query.payload if query.edns >= 0 else 512
                    for response in responses:
                        raw_response = (
                            response.to_wire(
                                multi=multi, max_size=max_size, prefer_truncation=True
                            )
                            if isinstance(response, dns.message.Message)
                            else response
                        )
                        await udp_socket.sendto(
                            raw_response,
                            client_context.remote_address,
                            client_context.remote_port,
                        )
        except TimeoutError:
            self.logger.warning("Timeout handling message")
        except Exception as exc:
            self.logger.error(f"Error responding to DNS query: {exc}", exc_info=exc)

    async def handle_socket_stream_client(
        self,
        socket_stream: SocketStream,
    ) -> None:
        """Process DNS queries received over a stream connection.

        Queries are read from the stream, each prefixed with a two byte
        length as specified by RFC 1035, section 4.2.2, and dispatched to
        :py:meth:`handle_query`; any responses are written back to the
        stream.  The connection is served until closed by the client, a
        timeout occurs, or an unparseable query is received.

        This method is used for both TCP and TLS connections.

        :param socket_stream: The stream over which the client is
            connected.
        :type socket_stream: :py:class:`anyio.abc.SocketStream`
        """

        client_context = DNSClientContext.from_socket_stream(socket_stream)

        self.logger.debug(
            "%s connection from %s:%d",
            client_context.transport.name.upper(),
            client_context.remote_address,
            client_context.remote_port,
        )

        buffered_stream = BufferedByteReceiveStream(socket_stream)

        try:
            while True:
                with anyio.fail_after(self.query_timeout):
                    query_length_bytes = await buffered_stream.receive_exactly(2)
                    (query_length,) = struct.unpack("!H", query_length_bytes)
                    raw_data = await buffered_stream.receive_exactly(query_length)

                try:
                    query = dns.message.from_wire(raw_data)
                except dns.exception.DNSException as exc:
                    self.logger.warning(f"Invalid query: {exc}", exc_info=exc)
                    return

                with anyio.fail_after(self.response_timeout):
                    if responses := await self.handle_query(
                        query=query,
                        client_context=client_context,
                    ):
                        for response in responses:
                            raw_response = (
                                response.to_wire(prepend_length=True)
                                if isinstance(response, dns.message.Message)
                                else response
                            )
                            await socket_stream.send(raw_response)
                        self.logger.debug("Returned %d DNS messages", len(responses))
        except (anyio.EndOfStream, anyio.IncompleteRead):
            self.logger.debug("TCP connection closed by client")
        except TimeoutError:
            self.logger.warning("Timeout handling message")
        except Exception as exc:
            self.logger.error(f"Error responding to DNS query: {exc}", exc_info=exc)

    async def validate_query(
        self,
        query: dns.message.Message,
        client_context: DNSClientContext,
    ) -> list[dns.message.Message | bytes] | None:
        """Validate a DNS query and return a response if invalid.

        :param query: The query to handle.
        :type query: :py:class:`dns.message.Message`
        :param client_context: The context of the client that sent the
            query.
        :type client_context: :py:class:`DNSClientContext`
        :returns: The response error messages to send.
        :rtype: list of :py:class:`dns.message.Message` or :py:class:`bytes`
            on error, or ``None`` if message is valid and should be processed
            by :py:meth:`query`.
        """

        # Silently ignore messages that are themselves responses (QR flag
        # set); answering them could create a reflection loop between servers
        if query.flags & dns.flags.QR:
            self.logger.warning("Ignoring message with QR flag set")
            return []

        # Reject queries that do not have exactly one question; RFC 1035, section 4.1.1,
        # requires that the question section contain exactly one question, and
        # RFC 2181, section 5.4.1, states that a server should respond with FORMERR to
        # queries that do not conform to this requirement.
        if len(query.question) != 1:
            self.logger.warning("Refusing query with %d questions", len(query.question))
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.FORMERR)
            return [response]

    async def handle_query(
        self,
        query: dns.message.Message,
        client_context: DNSClientContext,
    ) -> list[dns.message.Message | bytes]:
        """Handle a DNS query and dispatch it to :py:meth:`query`.

        :param query: The query to handle.
        :type query: :py:class:`dns.message.Message`
        :param client_context: The context of the client that sent the
            query.
        :type client_context: :py:class:`DNSClientContext`
        :returns: The response messages to send.
        :rtype: list of :py:class:`dns.message.Message` or :py:class:`bytes`
        """

        t1 = time.perf_counter()

        try:
            response_check = await self.validate_query(query, client_context)
            if response_check is not None:
                return response_check

            return await self.query(query, client_context)

        except Exception as exc:
            self.logger.warning(f"Query processing failed: {exc}")
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            return [response]

        finally:
            t2 = time.perf_counter()
            self.logger.debug("Created query response in %.3f seconds", t2 - t1)

    @abstractmethod
    async def query(
        self,
        query: dns.message.Message,
        client_context: DNSClientContext,
    ) -> list[dns.message.Message | bytes]:
        """Process a DNS query and return the responses.

        Subclasses must implement this method to provide the server's
        query processing logic.  The query is guaranteed to have exactly
        one question.

        :param query: The query to process.
        :type query: :py:class:`dns.message.Message`
        :param client_context: The context of the client that sent the
            query.
        :type client_context: :py:class:`DNSClientContext`
        :returns: The response messages to send.
        :rtype: list of :py:class:`dns.message.Message` or :py:class:`bytes`
        """
        pass


class ExampleDNSServer(DNSServer):
    """An example DNS server implementation.

    The server answers A queries for ``localhost.example.com`` with
    ``127.0.0.1`` and refuses all other queries.
    """

    async def query(
        self,
        query: dns.message.Message,
        client_context: DNSClientContext,
    ) -> list[dns.message.Message | bytes]:
        """Process a DNS query and return the responses.

        :param query: The query to process.
        :type query: :py:class:`dns.message.Message`
        :param client_context: The context of the client that sent the
            query.
        :type client_context: :py:class:`DNSClientContext`
        :returns: The response messages to send.
        :rtype: list of :py:class:`dns.message.Message` or :py:class:`bytes`
        """

        opcode = query.opcode()
        qname = query.question[0].name
        rdtype = query.question[0].rdtype
        rdclass = query.question[0].rdclass

        # Do not response to queries that do not have the Recursion Desired (RD) flag set
        if not query.flags & dns.flags.RD:
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.REFUSED)
            return [response]

        # Match the query against specific criteria and handle accordingly
        match (opcode, str(qname), rdtype, rdclass):
            case (
                dns.opcode.QUERY,
                "localhost.example.com.",
                dns.rdatatype.A,
                dns.rdataclass.IN,
            ):
                self.logger.info(
                    f"Handling {dns.rdatatype.to_text(rdtype)}/{dns.rdataclass.to_text(rdclass)} query for {qname}"
                    + f" from {client_context.transport} client"
                    + f" at {client_context.remote_address}:{client_context.remote_port}"
                    + f" on {client_context.local_address}:{client_context.local_port}"
                )
                # Here you would implement the logic to handle the A record query for localhost.example.com
                # For demonstration purposes, let's create a simple response
                response = dns.message.make_response(query)
                response.answer.append(
                    dns.rrset.from_text(
                        "localhost.example.com.",
                        300,
                        "IN",
                        "A",
                        "127.0.0.1",
                    )
                )
                return [response]
            case _:
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.REFUSED)
                return [response]


def main() -> None:
    """Run the example DNS server.

    The server listens on 127.0.0.1 with UDP and TCP on port 5300 and
    TLS on port 8853, using a self-signed certificate.
    """

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--listen",
        metavar="ADDRESS",
        type=str,
        help="Address to listen on",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--udp-port",
        metavar="PORT",
        type=int,
        help="UDP port to listen on (set to 0 to disable UDP)",
        default=8053,
    )
    parser.add_argument(
        "--tcp-port",
        metavar="PORT",
        type=int,
        help="TCP port to listen on (set to 0 to disable TCP)",
        default=8053,
    )
    parser.add_argument(
        "--tls-port",
        metavar="PORT",
        type=int,
        help="TLS port to listen on (set to 0 to disable TLS)",
        default=8853,
    )
    parser.add_argument(
        "--hostname",
        metavar="HOSTNAME",
        type=str,
        help="Hostname for self-signed TLS certificate",
        default="localhost",
    )
    parser.add_argument(
        "--certfile",
        metavar="CERTFILE",
        type=str,
        help="Path to TLS certificate file (self-signed if not provided)",
    )
    parser.add_argument(
        "--keyfile",
        metavar="KEYFILE",
        type=str,
        help="Path to TLS private key file (taken from certfile if not provided)",
    )

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    server = ExampleDNSServer()

    anyio.run(
        functools.partial(
            server.run,
            host=args.listen,
            listen_udp=args.udp_port or False,
            listen_tcp=args.tcp_port or False,
            listen_tls=args.tls_port or False,
            certfile=args.certfile,
            keyfile=args.keyfile,
            hostname=args.hostname,
        )
    )


if __name__ == "__main__":
    main()
