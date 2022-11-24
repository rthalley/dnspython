# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

try:
    import asyncio
    import socket
    import struct
    import threading

    import aioquic.asyncio
    import aioquic.asyncio.server
    import aioquic.quic.configuration
    import aioquic.quic.events

    import dns.asyncquery
    import dns.message
    import dns.rcode

    from tests.util import here

    have_quic = True

    class Request:
        def __init__(self, message, wire):
            self.message = message
            self.wire = wire

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

    class NanoQuic(aioquic.asyncio.QuicConnectionProtocol):
        def quic_event_received(self, event):
            # This is a bit hackish and not fully general, but this is a test server!
            if isinstance(event, aioquic.quic.events.StreamDataReceived):
                data = bytes(event.data)
                (wire_len,) = struct.unpack("!H", data[:2])
                wire = self.handle_wire(data[2 : 2 + wire_len])
                if wire is not None:
                    self._quic.send_stream_data(event.stream_id, wire, end_stream=True)

        def handle(self, request):
            r = dns.message.make_response(request.message)
            r.set_rcode(dns.rcode.REFUSED)
            return r

        def handle_wire(self, wire):
            response = None
            try:
                q = dns.message.from_wire(wire)
            except dns.message.ShortHeader:
                return
            except Exception as e:
                try:
                    q = dns.message.from_wire(wire, question_only=True)
                    response = dns.message.make_response(q)
                    response.set_rcode(dns.rcode.FORMERR)
                except Exception:
                    return
            if response is None:
                try:
                    request = Request(q, wire)
                    response = self.handle(request)
                except Exception:
                    response = dns.message.make_response(q)
                    response.set_rcode(dns.rcode.SERVFAIL)
            wire = response.to_wire()
            return struct.pack("!H", len(wire)) + wire

    class Server(threading.Thread):
        def __init__(self):
            super().__init__()
            self.transport = None
            self.protocol = None
            self.left = None
            self.right = None

        def __enter__(self):
            self.left, self.right = socket.socketpair()
            self.start()

        def __exit__(self, ex_ty, ex_va, ex_tr):
            if self.protocol is not None:
                self.protocol.close()
            if self.transport is not None:
                self.transport.close()
            if self.left:
                self.left.close()
            if self.is_alive():
                self.join()
            if self.right:
                self.right.close()

        async def arun(self):
            reader, _ = await asyncio.open_connection(sock=self.right)
            conf = aioquic.quic.configuration.QuicConfiguration(
                alpn_protocols=["doq"],
                is_client=False,
            )
            conf.load_cert_chain(here("tls/public.crt"), here("tls/private.pem"))
            loop = asyncio.get_event_loop()
            (self.transport, self.protocol) = await loop.create_datagram_endpoint(
                lambda: aioquic.asyncio.server.QuicServer(
                    configuration=conf, create_protocol=NanoQuic
                ),
                local_addr=("127.0.0.1", 8853),
            )
            try:
                await reader.read(1)
            except Exception:
                pass

        def run(self):
            asyncio.run(self.arun())

except ImportError:
    have_quic = False

    class NanoQuic:
        pass
