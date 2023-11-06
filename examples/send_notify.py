#!/usr/bin/python
"""
Minimalistic RFC 1996-like NOTIFY sender.
"""
import argparse
import ipaddress
import socket

import dns.flags
import dns.inet
import dns.message
import dns.name
import dns.opcode
import dns.query
import dns.rrset
import dns.rdataclass
import dns.rdatatype


def main():
    """Also prints all inputs and intermediate values"""
    parser = argparse.ArgumentParser(
        description="Send DNS NOTIFY mesage via UDP, optionally with synthetized SOA RR "
        "in ANSWER section. No checks. It's not RFC 1996 sect 3.6 compliant sender."
    )
    parser.add_argument("--source", type=ipaddress.ip_address, help="source IP address")
    parser.add_argument("--port", type=int, help="target port", default=53)
    parser.add_argument("target", type=ipaddress.ip_address, help="target IP address")
    parser.add_argument("zone", type=dns.name.from_text)
    parser.add_argument(
        "serial",
        nargs="?",
        type=int,
        help="optional serial - adds SOA RR into ANSWER section",
    )
    parser.add_argument(
        "--rdclass",
        default=dns.rdataclass.IN,
        type=dns.rdataclass.from_text,
        help="DNS class, defaults to IN",
    )
    args = parser.parse_args()
    if args.source:
        if dns.inet.af_for_address(str(args.target)) != dns.inet.af_for_address(
            str(args.source)
        ):
            parser.error("address family for source and target must be the same")

    print(args)
    msg = construct_msg(args)
    print(msg)
    udp_send(msg, args)


def construct_msg(args):
    """if args.serial is specified it creates fake SOA RR with given serial"""
    msg = dns.message.make_query(
        args.zone, dns.rdatatype.SOA, rdclass=args.rdclass, flags=dns.flags.AA
    )
    msg.set_opcode(dns.opcode.NOTIFY)
    if args.serial:
        soa = dns.rrset.from_text_list(
            name=args.zone,
            ttl=0,
            rdclass=args.rdclass,
            rdtype=dns.rdatatype.SOA,
            text_rdatas=[f". . {args.serial} 0 0 0 0"],
        )
        msg.answer.append(soa)
    return msg


def udp_send(msg, args):
    """ignores checks prescribed by RFC 1996 sect 3.6"""
    afam = dns.inet.af_for_address(str(args.target))
    sock = socket.socket(afam, socket.SOCK_DGRAM)
    if args.source:
        sock.bind((str(args.source), 0))
    dns.query.send_udp(sock, what=msg, destination=(str(args.target), args.port))


if __name__ == "__main__":
    main()
