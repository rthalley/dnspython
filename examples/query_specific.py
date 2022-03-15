#!/usr/bin/env python3

# Two ways of querying a specific nameserver.

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

# This way is just like nslookup/dig:

qname = dns.name.from_text("amazon.com")
q = dns.message.make_query(qname, dns.rdatatype.NS)
print("The query is:")
print(q)
print("")
r = dns.query.udp(q, "8.8.8.8")
print("The response is:")
print(r)
print("")
print("The nameservers are:")
ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
for rr in ns_rrset:
    print(rr.target)
print("")
print("")

# A higher-level way

import dns.resolver

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ["8.8.8.8"]
answer = resolver.resolve("amazon.com", "NS")
print("The nameservers are:")
for rr in answer:
    print(rr.target)

# Sending a query with the all flags set to 0.  This is the easiest way
# to make a query with the RD flag off.
#
# This sends a query with RD=0 for the root SOA RRset to the IP address
# for l.root-servers.net.

q = dns.message.make_query(".", dns.rdatatype.SOA, flags=0)
r = dns.query.udp(q, "199.7.83.42")
print("\nThe flags in the response are {}".format(dns.flags.to_text(r.flags)))
print('The SOA in the response is "{}"'.format((r.answer)[0][0]))
