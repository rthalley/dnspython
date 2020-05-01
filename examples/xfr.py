#!/usr/bin/env python3

import dns.query
import dns.resolver
import dns.zone

soa_answer = dns.resolver.query('dnspython.org', 'SOA')
master_answer = dns.resolver.query(soa_answer[0].mname, 'A')

z = dns.zone.from_xfr(dns.query.xfr(master_answer[0].address, 'dnspython.org'))
for n in sorted(z.nodes.keys()):
    print(z[n].to_text(n))
