#!/usr/bin/env python3
#
# Create a DNS server to receive DDNS update queries
#
# usage: ddns_server.py
#

import asyncio
import logging
import struct
import typing

import dns.exception
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsigkeyring
import dns.update


KEYRING = dns.tsigkeyring.from_text({"keyname.": "NjHwPsMKjdN++dOfE5iAiQ=="})

TEST_ZONES = {
    dns.name.from_text("example."): [
        dns.name.from_text("keyname."),
    ],
}


def response(msg, code=dns.rcode.SERVFAIL):
    response = dns.message.make_response(msg)
    response.set_rcode(code)
    return response.to_wire()


async def handle_nsupdate(data, addr):
    cli = addr[0]
    msg = dns.message.from_wire(data, keyring=KEYRING)
    try:
        if msg.opcode() != dns.opcode.UPDATE:
            raise NotImplementedError("Opcode %s not implemented" % dns.opcode.to_text(msg.opcode()))
        update_msg = typing.cast(dns.update.UpdateMessage, msg)
        zone = update_msg.zone[0].name
        if not msg.had_tsig or msg.keyname not in TEST_ZONES[zone]:
            raise dns.exception.DeniedByPolicy(f"Key {msg.keyname} not allowed for zone {zone}")
        for r in update_msg.update:
            if r.deleting:
                if r.deleting == dns.rdataclass.ANY and r.rdtype == dns.rdatatype.ANY:
                    logging.info("%s: delete_all_rrsets %s" % (cli, r))
                elif r.deleting == dns.rdataclass.ANY:
                    logging.info("%s: delete_rrset %s" % (cli, r))
                elif r.deleting == dns.rdataclass.NONE:
                    logging.info("%s: delete_from_rrset %s" % (cli, r))
            else:
                logging.info("%s: add_to_rrset %s" % (cli, r))
    except dns.exception.FormError:
        logging.exception("Rejected %s: Error parsing message" % cli)
        return response(msg, code=dns.rcode.FORMERR)
    except dns.exception.DeniedByPolicy:
        logging.exception("Rejected %s: Validation error" % cli)
        return response(msg, code=dns.rcode.REFUSED)
    except NotImplementedError:
        logging.exception("Rejected %s: Not implemented error" % cli)
        return response(msg, code=dns.rcode.NOTIMP)
    except:
        logging.exception("Rejected %s: Internal error" % cli)
        return response(msg, code=dns.rcode.SERVFAIL)
    return response(msg, code=dns.rcode.NOERROR)


async def main():
    hostname = "0.0.0.0"
    port = 8053

    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting servers at {hostname}:{port}")
    loop = asyncio.get_event_loop()

    # Start UDP server
    class DatagramProtocol(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, addr):
            asyncio.ensure_future(self.handle(data, addr))

        async def handle(self, data, addr):
            result = await handle_nsupdate(data, addr)
            self.transport.sendto(result, addr)

    transport, _protocol = await loop.create_datagram_endpoint(lambda: DatagramProtocol(), local_addr=(hostname, port))

    # Start TCP server
    class StreamReaderProtocol(asyncio.StreamReaderProtocol):
        def __init__(self):
            super().__init__(asyncio.StreamReader(), self.handle_tcp)

        async def handle_tcp(self, reader, writer):
            addr = writer.transport.get_extra_info("peername")
            while True:
                try:
                    (size,) = struct.unpack("!H", await reader.readexactly(2))
                except asyncio.IncompleteReadError:
                    break
                data = await reader.readexactly(size)

                result = await handle_nsupdate(data, addr)
                bsize = struct.pack("!H", len(result))
                writer.write(bsize)
                writer.write(result)

    server = await loop.create_server(lambda: StreamReaderProtocol(), hostname, port)
    await server.serve_forever()


asyncio.run(main())
