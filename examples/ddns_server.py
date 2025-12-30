#!/usr/bin/env python3
#
# Create a DNS server to receive DDNS update queries
#
# usage: ddns_server.py
#

import asyncio
import logging
import typing

import dns.asyncserver
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


async def handle_nsupdate(msg: dns.message.Message, addr):
    cli = addr[0]
    if msg.opcode() != dns.opcode.UPDATE:
        raise NotImplementedError("Opcode %s not implemented" % dns.opcode.to_text(msg.opcode()))
    update_msg = typing.cast(dns.update.UpdateMessage, msg)
    zone = update_msg.zone[0].name
    if not msg.had_tsig or msg.keyname not in TEST_ZONES[zone]:
        raise dns.exception.ValidationFailure(f"Key {msg.keyname} not allowed for zone {zone}")
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
    response = dns.message.make_response(msg)
    response.set_rcode(dns.rcode.NOERROR)
    return response


async def main():
    hostname = "0.0.0.0"
    port = 8053

    logging.basicConfig(level=logging.INFO)
    logging.info(f"Starting servers at {hostname}:{port}")

    async with asyncio.TaskGroup() as tg:
        tg.create_task(
            dns.asyncserver.udp_serve(
                handle_nsupdate,
                hostname,
                port,
                KEYRING,
                one_rr_per_rrset=True,
            ),
        )
        tg.create_task(
            dns.asyncserver.tcp_serve(
                handle_nsupdate,
                hostname,
                port,
                KEYRING,
                one_rr_per_rrset=True,
            ),
        )


asyncio.run(main())
