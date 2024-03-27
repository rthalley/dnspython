# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import contextlib
import enum
import errno
import functools
import logging
import logging.config
import socket
import ssl
import struct
import threading

import trio

import dns.asyncquery
import dns.inet
import dns.message
import dns.rcode
from tests.util import here

try:
    import tests.doq

    have_doq = True
except Exception:
    have_doq = False

try:
    import tests.doh

    have_doh = True
except Exception as e:
    have_doh = False


class ConnectionType(enum.IntEnum):
    UDP = 1
    TCP = 2
    DOT = 3
    DOH = 4
    DOQ = 5
    DOH3 = 6


async def read_exactly(stream, count):
    """Read the specified number of bytes from stream.  Keep trying until we
    either get the desired amount, or we hit EOF.
    """
    s = b""
    while count > 0:
        n = await stream.receive_some(count)
        if n == b"":
            raise EOFError
        count = count - len(n)
        s = s + n
    return s


class Request:
    def __init__(self, message, wire, peer, local, connection_type):
        self.message = message
        self.wire = wire
        self.peer = peer
        self.local = local
        self.connection_type = connection_type

    @property
    def question(self):
        return self.message.question[0]

    @property
    def qname(self):
        return self.question.name

    @property
    def qclass(self):
        return self.question.rdclass

    @property
    def qtype(self):
        return self.question.rdtype


class Server(threading.Thread):
    """The nanoserver is a nameserver skeleton suitable for faking a DNS
    server for various testing purposes.  It executes with a trio run
    loop in a dedicated thread, and is a context manager.  Exiting the
    context manager will ensure the server shuts down.

    If a port is not specified, random ports will be chosen.

    Applications should subclass the server and override the handle()
    method to determine how the server responds to queries.  The
    default behavior is to refuse everything.

    If use_thread is set to False in the constructor, then the
    server's main() method can be used directly in a trio nursery,
    allowing the server's cancellation to be managed in the Trio way.
    In this case, no thread creation ever happens even though Server
    is a subclass of thread, because the start() method is never
    called.
    """

    def __init__(
        self,
        *,
        address="127.0.0.1",
        port=0,
        dot_port=0,
        doh_port=0,
        protocols=tuple(p for p in ConnectionType),
        use_thread=True,
        origin=None,
        keyring=None,
        tls_chain=here("tls/public.crt"),
        tls_key=here("tls/private.pem"),
    ):
        super().__init__()
        self.address = address
        self.port = port
        self.dot_port = dot_port
        self.doh_port = doh_port
        self.protocols = set(protocols)
        if not have_doq:
            self.protocols.discard(ConnectionType.DOQ)
        if not have_doh:
            self.protocols.discard(ConnectionType.DOH)
            self.protocols.discard(ConnectionType.DOH3)
        self.use_thread = use_thread
        self.origin = origin
        self.keyring = keyring
        self.left = None
        self.right = None
        self.sockets = {}
        self.addresses = {}
        self.tls_chain = tls_chain
        self.tls_key = tls_key

    def get_address(self, connection_type):
        return self.addresses[connection_type]

    # For backwards compatibility
    @property
    def udp_address(self):
        return self.addresses[ConnectionType.UDP]

    @property
    def tcp_address(self):
        return self.addresses[ConnectionType.TCP]

    @property
    def doq_address(self):
        return self.addresses[ConnectionType.DOQ]

    def caught(self, who, e):
        print(who, "caught", type(e), e)

    def open_sockets(self, port, udp_type, tcp_type):
        want_udp = udp_type in self.protocols
        want_tcp = tcp_type in self.protocols
        udp = None
        tcp = None
        af = dns.inet.af_for_address(self.address)

        if port != 0 or not (want_udp and want_tcp):
            if want_udp:
                udp = socket.socket(af, socket.SOCK_DGRAM, 0)
                udp.bind((self.address, port))
                self.sockets[udp_type] = udp
            if want_tcp:
                tcp = socket.create_server((self.address, port), family=af)
                self.sockets[tcp_type] = tcp
            return

        open_udp_sockets = []
        try:
            while True:
                udp = socket.socket(af, socket.SOCK_DGRAM, 0)
                udp.bind((self.address, port))
                try:
                    udp_port = udp.getsockname()[1]
                    tcp = socket.create_server((self.address, udp_port), family=af)
                    self.sockets[udp_type] = udp
                    self.sockets[tcp_type] = tcp
                    return
                except OSError:
                    # We failed to open the corresponding TCP port.  Keep the UDP socket
                    # open, try again, and hope we get a better port.
                    if len(open_udp_sockets) < 100:
                        open_udp_sockets.append(udp)
                        continue
                    # 100 tries to find a port is enough!  Give up!
                    raise
        finally:
            for udp_socket in open_udp_sockets:
                udp_socket.close()

    def __enter__(self):
        (self.left, self.right) = socket.socketpair()
        # We're making the sockets now so they can be sent to by the
        # caller immediately (i.e. no race with the listener starting
        # in the thread).
        self.open_sockets(self.port, ConnectionType.UDP, ConnectionType.TCP)
        self.open_sockets(self.dot_port, ConnectionType.DOQ, ConnectionType.DOT)
        self.open_sockets(self.doh_port, ConnectionType.DOH3, ConnectionType.DOH)
        for proto, sock in self.sockets.items():
            self.addresses[proto] = sock.getsockname()
        if self.use_thread:
            self.start()
        return self

    def __exit__(self, ex_ty, ex_va, ex_tr):
        if self.left:
            self.left.close()
        if self.use_thread and self.is_alive():
            self.join()
        if self.right:
            self.right.close()
        for sock in self.sockets.values():
            sock.close()

    async def wait_for_input_or_eof(self):
        #
        # This trio task just waits for input on the right half of the
        # socketpair (the left half is owned by the context manager
        # returned by launch).  As soon as something is read, or the
        # socket returns EOF, EOFError is raised, causing a the
        # nursery to cancel all other nursery tasks, in particular the
        # listeners.
        #
        try:
            with trio.socket.from_stdlib_socket(self.right) as sock:
                self.right = None  # we own cleanup
                await sock.recv(1)
        finally:
            raise EOFError

    def handle(self, request):
        #
        # Handle request 'request'.  Override this method to change
        # how the server behaves.
        #
        # The return value is either a dns.message.Message, a bytes,
        # None, or a list of one of those.  We allow a bytes to be
        # returned for cases where handle wants to return an invalid
        # DNS message for testing purposes.  We allow None to be
        # returned to indicate there is no response.  If a list is
        # returned, then the output code will run for each returned
        # item.
        #
        r = dns.message.make_response(request.message)
        r.set_rcode(dns.rcode.REFUSED)
        return r

    def maybe_listify(self, thing):
        if isinstance(thing, list):
            return thing
        else:
            return [thing]

    def handle_wire(self, wire, peer, local, connection_type):
        #
        # This is the common code to parse wire format, call handle() on
        # the message, and then generate response wire format (if handle()
        # didn't do it).
        #
        # It also handles any exceptions from handle()
        #
        # Returns a (possibly empty) list of wire format message to send.
        items = []
        r = None
        try:
            q = dns.message.from_wire(wire, keyring=self.keyring)
        except dns.message.ShortHeader:
            # There is no hope of answering this one!
            return
        except Exception:
            # Try to make a FORMERR using just the question section.
            try:
                q = dns.message.from_wire(wire, question_only=True)
                r = dns.message.make_response(q)
                r.set_rcode(dns.rcode.FORMERR)
                items.append(r)
            except Exception:
                # We could try to make a response from only the header
                # if dnspython had a header_only option to
                # from_wire(), or if we truncated wire ourselves, but
                # for now we just drop.
                return
        try:
            # items might have been appended to above, so skip
            # handle() if we already have a response.
            if not items:
                request = Request(q, wire, peer, local, connection_type)
                items = self.maybe_listify(self.handle(request))
        except Exception as e:
            # Exceptions from handle get a SERVFAIL response, and a print because
            # they are usually bugs in the the test!
            self.caught("handle", e)
            r = dns.message.make_response(q)
            r.set_rcode(dns.rcode.SERVFAIL)
            items = [r]

        tsig_ctx = None
        multi = len(items) > 1
        for thing in items:
            if isinstance(thing, dns.message.Message):
                out = thing.to_wire(self.origin, multi=multi, tsig_ctx=tsig_ctx)
                tsig_ctx = thing.tsig_ctx
                yield out
            elif thing is not None:
                yield thing

    async def serve_udp(self, connection_type):
        with trio.socket.from_stdlib_socket(self.sockets[connection_type]) as sock:
            self.sockets.pop(connection_type)  # we own cleanup
            local = self.addresses[connection_type]
            while True:
                try:
                    (wire, peer) = await sock.recvfrom(65535)
                    for wire in self.handle_wire(wire, peer, local, connection_type):
                        await sock.sendto(wire, peer)
                except Exception as e:
                    self.caught("serve_udp", e)

    async def serve_tcp(self, connection_type, stream):
        try:
            if connection_type == ConnectionType.DOT:
                peer = stream.transport_stream.socket.getpeername()
                local = stream.transport_stream.socket.getsockname()
            else:
                assert connection_type == ConnectionType.TCP
                peer = stream.socket.getpeername()
                local = stream.socket.getsockname()
            while True:
                ldata = await read_exactly(stream, 2)
                (l,) = struct.unpack("!H", ldata)
                wire = await read_exactly(stream, l)
                for wire in self.handle_wire(wire, peer, local, connection_type):
                    l = len(wire)
                    stream_message = struct.pack("!H", l) + wire
                    await stream.send_all(stream_message)
        except Exception as e:
            self.caught("serve_tcp", e)

    async def orchestrate_tcp(self, connection_type):
        with trio.socket.from_stdlib_socket(self.sockets[connection_type]) as sock:
            self.sockets.pop(connection_type)  # we own cleanup
            listener = trio.SocketListener(sock)
            if connection_type == ConnectionType.DOT:
                ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
                ssl_context.load_cert_chain(self.tls_chain, self.tls_key)
                listener = trio.SSLListener(listener, ssl_context)
            serve = functools.partial(self.serve_tcp, connection_type)
            async with trio.open_nursery() as nursery:
                serve = functools.partial(
                    trio.serve_listeners,
                    serve,
                    [listener],
                    handler_nursery=nursery,
                )
                nursery.start_soon(serve)

    async def serve_doq(self, connection_type) -> None:
        with trio.socket.from_stdlib_socket(self.sockets[connection_type]) as sock:
            self.sockets.pop(connection_type)  # we own cleanup
            async with tests.doq.Listener(
                self, sock, connection_type, self.tls_chain, self.tls_key
            ) as listener:
                try:
                    await listener.run()
                except Exception as e:
                    self.caught("serve_doq", e)

    async def serve_doh(self, connection_type) -> None:
        server = tests.doh.make_server(
            self,
            self.sockets[connection_type],
            connection_type,
            self.tls_chain,
            self.tls_key,
        )
        try:
            await server()
        except Exception as e:
            self.caught("serve_doh", e)

    async def main(self):
        handlers = {
            ConnectionType.UDP: self.serve_udp,
            ConnectionType.TCP: self.orchestrate_tcp,
            ConnectionType.DOT: self.orchestrate_tcp,
            ConnectionType.DOH: self.serve_doh,
            ConnectionType.DOH3: self.serve_doh,
            ConnectionType.DOQ: self.serve_doq,
        }

        try:
            async with trio.open_nursery() as nursery:
                if self.use_thread:
                    nursery.start_soon(self.wait_for_input_or_eof)
                for connection_type in self.protocols:
                    nursery.start_soon(handlers[connection_type], connection_type)

        except Exception as e:
            self.caught("nanoserver main", e)

    def run(self):
        if not self.use_thread:
            raise RuntimeError("start() called on a use_thread=False Server")
        trio.run(self.main)


if __name__ == "__main__":
    import sys
    import time

    logger = logging.getLogger(__name__)
    format = "%(asctime)s %(levelname)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO)
    logging.config.dictConfig(
        {
            "version": 1,
            "incremental": True,
            "loggers": {
                "quart.app": {
                    "level": "INFO",
                },
                "quart.serving": {
                    "propagate": False,
                    "level": "ERROR",
                },
                "quic": {
                    "level": "CRITICAL",
                },
            },
        }
    )

    async def trio_main():
        try:
            with Server(
                port=5354, dot_port=5355, doh_port=5356, use_thread=False
            ) as server:
                print("Trio mode")
                for proto, address in server.addresses.items():
                    print(f"  listening on {proto.name}: {address}")
                async with trio.open_nursery() as nursery:
                    nursery.start_soon(server.main)
        except Exception as e:
            print("trio_main caught", type(e), e)

    def threaded_main():
        with Server(port=5354, dot_port=5355, doh_port=5356) as server:
            print("Thread mode")
            for proto, address in server.addresses.items():
                print(f"  listening on {proto.name}: {address}")
            time.sleep(300)

    if len(sys.argv) > 1 and sys.argv[1] == "trio":
        trio.run(trio_main)
    else:
        threaded_main()
