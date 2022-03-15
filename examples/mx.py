#!/usr/bin/env python3

import dns.resolver

answers = dns.resolver.resolve("nominum.com", "MX")
for rdata in answers:
    print("Host", rdata.exchange, "has preference", rdata.preference)
