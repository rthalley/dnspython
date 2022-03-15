#!/usr/bin/env python3

import dns.edns
import dns.message
import dns.query
import dns.resolver

n = "."
t = dns.rdatatype.SOA
l = "google.com"  # Address of l.root-servers.net, '199.7.83.42'
i = "ns1.isc.org"  # Address of ns1.isc.org, for COOKIEs, '149.20.1.73'

o_list = []

# A query without options
o_list.append((l, dict()))

# The same query, but with empty options list
o_list.append((l, dict(options=[])))

# Use use_edns() to specify EDNS0 options, such as buffer size
o_list.append((l, dict(payload=2000)))

# With an NSID option, but with use_edns() to specify the options
edns_kwargs = dict(
    edns=0, options=[dns.edns.GenericOption(dns.edns.OptionType.NSID, b"")]
)
o_list.append((l, edns_kwargs))

# With a COOKIE
o_list.append(
    (
        i,
        dict(
            options=[
                dns.edns.GenericOption(
                    dns.edns.OptionType.COOKIE, b"0xfe11ac99bebe3322"
                )
            ]
        ),
    )
)

# With an ECS option using cloudflare dns address
o_list.append((l, dict(options=[dns.edns.ECSOption("1.1.1.1", 24)])))

# With an ECS option using the current machine address
import urllib.request

external_ip = urllib.request.urlopen("https://ident.me").read().decode("utf8")

o_list.append((l, dict(options=[dns.edns.ECSOption(external_ip, 24)])))

aresolver = dns.resolver.Resolver()

for (addr, edns_kwargs) in o_list:
    if edns_kwargs:
        aresolver.use_edns(**edns_kwargs)
    aresolver.nameservers = ["8.8.8.8"]
    print(list(aresolver.resolve(addr, "A")))
