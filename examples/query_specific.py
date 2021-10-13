#!/usr/bin/env python3

# Two ways of querying a specific nameserver.

import dns.message
import dns.rdataclass
import dns.rdatatype
import dns.query

# This way is just like nslookup/dig:

qname = dns.name.from_text('amazon.com')
q = dns.message.make_query(qname, dns.rdatatype.NS)
# To include EDNS0 options, you need to include two options
#    in the call to dns.message.make_query. For example, to add NSID:
#    use_edns=0,
#    options=[dns.edns.GenericOption(dns.edns.OptionType.NSID, b'')]
print('The query is:')
print(q)
print('')
r = dns.query.udp(q, '8.8.8.8')
print('The response is:')
print(r)
print('')
print('The nameservers are:')
ns_rrset = r.find_rrset(r.answer, qname, dns.rdataclass.IN, dns.rdatatype.NS)
for rr in ns_rrset:
    print(rr.target)
print('')
print('')

# A higher-level way

import dns.resolver

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8']
answer = resolver.resolve('amazon.com', 'NS')
print('The nameservers are:')
for rr in answer:
    print(rr.target)
