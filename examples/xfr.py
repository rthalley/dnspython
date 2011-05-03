#!/usr/bin/env python

import dns.query
import dns.zone

z = dns.zone.from_xfr(dns.query.xfr('78.32.75.15', 'dnspython.org'))
names = sorted(z)
for n in names:
        print(z[n].to_text(n))
