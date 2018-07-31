#!/usr/bin/env python3

# This is just a toy, real code would check that the received message
# really was a NOTIFY, and otherwise handle errors.

from __future__ import print_function

import socket

import dns.flags
import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.name

from typing import cast

address = '127.0.0.1'
port = 53535

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((address, port))
while True:
    (wire, address) = s.recvfrom(512)
    notify = dns.message.from_wire(wire)
    soa = notify.find_rrset(notify.answer, notify.question[0].name,
                            dns.rdataclass.IN, dns.rdatatype.SOA)

    # Do something with the SOA RR here
    print('The serial number for', soa.name, 'is', soa[0].serial)

    response = dns.message.make_response(notify) # type: dns.message.Message
    response.flags |= dns.flags.AA
    wire = response.to_wire(cast(dns.name.Name, response))
    s.sendto(wire, address)
