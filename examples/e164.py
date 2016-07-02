#!/usr/bin/env python

from __future__ import print_function

import dns.e164
n = dns.e164.from_e164("+1 555 1212")
print(n)
print(dns.e164.to_e164(n))
