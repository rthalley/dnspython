#!/usr/bin/env python3

import dns.query
import dns.resolver
import dns.zone

# Note that running this doesn't currently work because
# dnspython.org's nameservers do not permit AXFR

soa_answer = dns.resolver.resolve("dnspython.org", "SOA")
master_answer = dns.resolver.resolve(soa_answer[0].mname, "A")

z = dns.zone.Zone("dnspython.org")
dns.query.inbound_xfr(master_answer[0].address, z)
for n in sorted(z.nodes.keys()):
    print(z[n].to_text(n))
