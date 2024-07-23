#!/usr/bin/env python3

import dns.message
import dns.query
import dns.tsig

key = dns.tsig.Key(
    "keyname.",
    "bnp6+y85UcBfsieuB/Uhx3EUsjc8wAFyyCSS5rhScb0=",
    algorithm=dns.tsig.HMAC_SHA256,
)


q = dns.message.make_query("example.", "SOA")
q.use_tsig(keyring=key)
r = dns.query.udp(q, "127.0.0.1")  # your authority address here
soa = r.find_rrset(r.answer, "example", "IN", "SOA")
print(soa)
