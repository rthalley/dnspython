# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Implement DNS-over-QUIC

import secrets
import struct
import time
from typing import Optional, Set, Tuple, Union

import aioquic
import aioquic.buffer
import aioquic.quic.configuration
import aioquic.quic.connection
import aioquic.quic.events
import aioquic.quic.logger
import aioquic.quic.packet
import aioquic.quic.retry
import trio

import dns.exception
from dns._asyncbackend import NullContext
from dns.quic._common import Buffer

MAX_SAVED_SESSIONS = 100


class Stream:
    def __init__(self, connection, stream_id):
        self.connection = connection
        self.stream_id = stream_id
        self.buffer = Buffer()
        self.expecting = 0
        self.wake_up = trio.Condition()
        self.headers = None
        self.trailers = None

    async def wait_for(self, amount: int):
        while True:
            if self.buffer.have(amount):
                return
            self.expecting = amount
            async with self.wake_up:
                await self.wake_up.wait()
            self.expecting = 0

    async def receive(self, timeout: Optional[float] = None):
        context: Union[trio.CancelScope, NullContext]
        if timeout is None:
            context = NullContext(None)
        else:
            context = trio.move_on_after(timeout)
        with context:
            await self.wait_for(2)
            (size,) = struct.unpack("!H", self.buffer.get(2))
            await self.wait_for(size)
            return self.buffer.get(size)
        raise dns.exception.Timeout

    async def send(self, datagram: bytes, is_end=False):
        l = len(datagram)
        data = struct.pack("!H", l) + datagram
        await self.connection.write(self.stream_id, data, is_end)

    async def add_input(self, data: bytes, is_end: bool):
        self.buffer.put(data, is_end)
        # Note it is important that we wake up if we're ending!
        if (self.expecting > 0 and self.buffer.have(self.expecting)) or is_end:
            async with self.wake_up:
                self.wake_up.notify()

    def seen_end(self) -> bool:
        return self.buffer.seen_end()

    async def run(self):
        try:
            wire = await self.receive()
            is_get = False
            path: Optional[bytes]
            for wire in self.connection.listener.server.handle_wire(
                wire,
                self.connection.peer,
                self.connection.listener.socket.getsockname(),
                self.connection.listener.connection_type,
            ):
                break
            await self.send(wire, True)
        except Exception:
            if not self.seen_end():
                self.connection.reset(self.stream_id)
        finally:
            self.connection.stream_done(self)


class Connection:
    def __init__(self, listener, cid, peer, retry_cid=None):
        self.original_cid: bytes = cid
        self.listener = listener
        self.cids: Set[bytes] = set()
        self.cids.add(cid)
        self.listener.connections[cid] = self
        self.peer = peer
        self.quic_connection = aioquic.quic.connection.QuicConnection(
            configuration=listener.quic_config,
            original_destination_connection_id=cid,
            retry_source_connection_id=retry_cid,
            session_ticket_fetcher=self.listener.pop_session_ticket,
            session_ticket_handler=self.listener.store_session_ticket,
        )
        self.cids.add(self.quic_connection.host_cid)
        self.listener.connections[self.quic_connection.host_cid] = self
        self.send_channel: trio.MemorySendChannel
        self.receive_channel: trio.MemoryReceiveChannel
        self.send_channel, self.receive_channel = trio.open_memory_channel(100)
        self.send_pending = False
        self.done = False
        self.worker_scope = None
        self.streams = {}

    def get_timer_values(self, now: float) -> Tuple[float, float]:
        expiration = self.quic_connection.get_timer()
        if expiration is None:
            expiration = now + 3600  # arbitrary "big" value
        interval = max(expiration - now, 0)
        return (expiration, interval)

    async def close_open_streams(self):
        # We copy the list here as awaiting might let the dictionary change
        # due to the stream finishing.
        for stream in list(self.streams.values()):
            if not stream.seen_end():
                await stream.add_input(b"", True)

    def create_stream(self, nursery: trio.Nursery, stream_id: int) -> Stream:
        stream = Stream(self, stream_id)
        self.streams[stream_id] = stream
        nursery.start_soon(stream.run)
        return stream

    async def handle_events(self, nursery: trio.Nursery):
        count = 0
        while not self.done:
            event = self.quic_connection.next_event()
            if event is None:
                return
            if isinstance(event, aioquic.quic.events.StreamDataReceived):
                stream = self.streams.get(event.stream_id)
                if stream is None:
                    stream = self.create_stream(nursery, event.stream_id)
                await stream.add_input(event.data, event.end_stream)
            elif isinstance(event, aioquic.quic.events.ConnectionTerminated):
                await self.close_open_streams()
                self.done = True
            elif isinstance(event, aioquic.quic.events.ConnectionIdIssued):
                cid = event.connection_id
                if cid not in self.cids:
                    self.cids.add(cid)
                    self.listener.connections[cid] = self
                else:
                    self.done = True
            elif isinstance(event, aioquic.quic.events.ConnectionIdRetired):
                cid = event.connection_id
                if cid in self.cids:
                    # These should not fail but we eat them just in case so we
                    # don't crash the whole connection.
                    self.cids.remove(cid)
                    del self.listener.connections[cid]
                else:
                    self.done = True
            count += 1
            if count > 10:
                # yield
                count = 0
                await trio.sleep(0)

    async def run(self):
        try:
            async with trio.open_nursery() as nursery:
                while not self.done:
                    now = time.time()
                    (expiration, interval) = self.get_timer_values(now)
                    # Note it must be trio.current_time() and not now due to how
                    # trio time works!
                    if self.send_pending:
                        interval = 0
                        self.send_pending = False
                    with trio.CancelScope(
                        deadline=trio.current_time() + interval
                    ) as self.worker_scope:
                        (datagram, peer) = await self.receive_channel.receive()
                        self.quic_connection.receive_datagram(datagram, peer, now)
                    self.worker_scope = None
                    now = time.time()
                    if expiration <= now:
                        self.quic_connection.handle_timer(now)
                    await self.handle_events(nursery)
                    datagrams = self.quic_connection.datagrams_to_send(now)
                    for datagram, _ in datagrams:
                        await self.listener.socket.sendto(datagram, self.peer)
        finally:
            await self.close_open_streams()
            for cid in self.cids:
                try:
                    del self.listener.connections[cid]
                except KeyError:
                    pass

    def maybe_wake_up(self):
        self.send_pending = True
        if self.worker_scope is not None:
            self.worker_scope.cancel()

    async def write(self, stream: int, data: bytes, is_end=False):
        if not self.done:
            self.quic_connection.send_stream_data(stream, data, is_end)
            self.maybe_wake_up()

    def reset(self, stream: int, error=0):
        if not self.done:
            self.quic_connection.reset_stream(stream, error)
            self.maybe_wake_up()

    def stream_done(self, stream: Stream):
        try:
            del self.streams[stream.stream_id]
        except KeyError:
            pass


class Listener:
    def __init__(
        self,
        server,
        socket,
        connection_type,
        tls_chain,
        tls_key,
        quic_log_directory=None,
        quic_retry=False,
    ):
        self.server = server
        self.socket = socket  # note this is a trio socket
        self.connection_type = connection_type
        self.connections = {}
        self.session_tickets = {}
        self.done = False
        alpn_protocols = ["doq"]
        self.quic_config = aioquic.quic.configuration.QuicConfiguration(
            is_client=False, alpn_protocols=alpn_protocols
        )
        if quic_log_directory is not None:
            self.quic_config.quic_logger = aioquic.quic.logger.QuicFileLogger(
                quic_log_directory
            )
        self.quic_config.load_cert_chain(tls_chain, tls_key)
        self.retry: Optional[aioquic.quic.retry.QuicRetryTokenHandler]
        if quic_retry:
            self.retry = aioquic.quic.retry.QuicRetryTokenHandler()
        else:
            self.retry = None

    def pop_session_ticket(self, key):
        try:
            return self.session_tickets.pop(key)
        except KeyError:
            return None

    def store_session_ticket(self, session_ticket):
        self.session_tickets[session_ticket.ticket] = session_ticket
        while len(self.session_tickets) > MAX_SAVED_SESSIONS:
            # Grab the first key
            key = next(iter(self.session_tickets.keys()))
            del self.session_tickets[key]

    async def run(self):
        async with trio.open_nursery() as nursery:
            while True:
                data = None
                peer = None
                try:
                    (data, peer) = await self.socket.recvfrom(65535)
                except Exception:
                    continue
                buffer = aioquic.buffer.Buffer(data=data)
                try:
                    header = aioquic.quic.packet.pull_quic_header(
                        buffer, self.quic_config.connection_id_length
                    )
                except Exception:
                    continue
                cid = header.destination_cid
                connection = self.connections.get(cid)
                if (
                    connection is None
                    and header.version is not None
                    and len(data) >= 1200
                    and header.version not in self.quic_config.supported_versions
                ):
                    wire = aioquic.quic.packet.encode_quic_version_negotiation(
                        source_cid=cid,
                        destination_cid=header.source_cid,
                        supported_versions=self.quic_config.supported_versions,
                    )
                    await self.socket.sendto(wire, peer)
                    continue

                if (
                    connection is None
                    and len(data) >= 1200
                    and header.packet_type == aioquic.quic.packet.PACKET_TYPE_INITIAL
                ):
                    retry_cid = None
                    if self.retry is not None:
                        if not header.token:
                            if header.version is None:
                                continue
                            source_cid = secrets.token_bytes(8)
                            wire = aioquic.quic.packet.encode_quic_retry(
                                version=header.version,
                                source_cid=source_cid,
                                destination_cid=header.source_cid,
                                original_destination_cid=header.destination_cid,
                                retry_token=self.retry.create_token(
                                    peer, header.destination_cid, source_cid
                                ),
                            )
                            await self.socket.sendto(wire, peer)
                            continue
                        else:
                            try:
                                (cid, retry_cid) = self.retry.validate_token(
                                    peer, header.token
                                )
                                # We need to recheck the cid here in case of duplicates,
                                # as we don't want to kick off another connection!
                                connection = self.connections.get(cid)
                                if connection is not None:
                                    # duplicate!
                                    continue
                            except ValueError:
                                continue

                    connection = Connection(self, cid, peer, retry_cid)
                    nursery.start_soon(connection.run)

                if connection is not None:
                    try:
                        connection.send_channel.send_nowait((data, peer))
                    except trio.WouldBlock:
                        pass

    # Listeners are async context managers

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return False
