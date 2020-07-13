#!/usr/bin/env python3

import copy
import json
import requests

import dns.flags
import dns.message
import dns.resolver
import dns.rdataclass
import dns.rdatatype

# This shows how to convert to/from dnspython's message object and the
# DNS-over-HTTPS (DoH) JSON form used by Google and Cloudflare, and
# described here:
#
#     https://developers.google.com/speed/public-dns/docs/doh/json
#
# There's no need to do this for DoH as dnspython supports the
# standard RFC 8484 protocol which all DoH providers implement.  The
# conversion to/from JSON is useful, however, so we show a way to do
# it.
#
# "simple" below means "simple python data types", i.e. things made of
# combinations of dictionaries, lists, strings, and numbers.

def make_rr(simple, rdata):
    csimple = copy.copy(simple)
    csimple['data'] = rdata.to_text()
    return csimple

def flatten_rrset(rrs):
    simple = {
        'name': str(rrs.name),
        'type': rrs.rdtype,
    }
    if len(rrs) > 0:
        simple['TTL'] = rrs.ttl
        return [make_rr(simple, rdata) for rdata in rrs]
    else:
        return [simple]

def to_doh_simple(message):
    simple = {
        'Status': message.rcode()
    }
    for f in dns.flags.Flag:
        if f != dns.flags.Flag.AA and f != dns.flags.Flag.QR:
            # DoH JSON doesn't need AA and omits it.  DoH JSON is only
            # used in replies so the QR flag is implied.
            simple[f.name] = (message.flags & f) != 0
    for i, s in enumerate(message.sections):
        k = dns.message.MessageSection.to_text(i).title()
        simple[k] = []
        for rrs in s:
            simple[k].extend(flatten_rrset(rrs))
    # we don't encode the ecs_client_subnet field
    return simple

def from_doh_simple(simple, add_qr=False):
    message = dns.message.QueryMessage()
    flags = 0
    for f in dns.flags.Flag:
        if simple.get(f.name, False):
            flags |= f
    if add_qr:  # QR is implied
        flags |= dns.flags.QR
    message.flags = flags
    message.set_rcode(simple.get('Status', 0))
    for i, sn in enumerate(dns.message.MessageSection):
        rr_list = simple.get(sn.name.title(), [])
        for rr in rr_list:
            rdtype = dns.rdatatype.RdataType(rr['type'])
            rrs = message.find_rrset(i, dns.name.from_text(rr['name']),
                                     dns.rdataclass.IN, rdtype,
                                     create=True)
            if 'data' in rr:
                rrs.add(dns.rdata.from_text(dns.rdataclass.IN, rdtype,
                                            rr['data']), rr.get('TTL', 0))
    # we don't decode the ecs_client_subnet field
    return message


a = dns.resolver.resolve('www.dnspython.org', 'a')
p = to_doh_simple(a.response)
print(json.dumps(p, indent=4))
response = requests.get('https://dns.google/resolve?', verify=True,
                        params={'name': 'www.dnspython.org',
                                'type': 1})
p = json.loads(response.text)
m = from_doh_simple(p, True)
print(m)
