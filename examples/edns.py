#!/usr/bin/env python3

import dns.edns
import dns.message
import dns.query
import dns.resolver

n = "."
t = dns.rdatatype.SOA
l = "199.7.83.42"  # Address of l.root-servers.net
i = "149.20.1.73"  # Address of ns1.isc.org, for COOKIEs

q_list = []

# A query without EDNS0
q_list.append((l, dns.message.make_query(n, t)))

# The same query, but with EDNS0 turned on with no options
q_list.append((l, dns.message.make_query(n, t, use_edns=0)))

# Use use_edns() to specify EDNS0 options, such as buffer size
this_q = dns.message.make_query(n, t)
this_q.use_edns(0, payload=2000)
q_list.append((l, this_q))

# With an NSID option
#   use_edns=0 is not needed if options are specified)
q_list.append(
    (
        l,
        dns.message.make_query(
            n, t, options=[dns.edns.GenericOption(dns.edns.OptionType.NSID, b"")]
        ),
    )
)

# With an NSID option, but with use_edns() to specify the options
this_q = dns.message.make_query(n, t)
this_q.use_edns(0, options=[dns.edns.GenericOption(dns.edns.OptionType.NSID, b"")])
q_list.append((l, this_q))

# With a COOKIE
q_list.append(
    (
        i,
        dns.message.make_query(
            n,
            t,
            options=[
                dns.edns.GenericOption(
                    dns.edns.OptionType.COOKIE, b"0xfe11ac99bebe3322"
                )
            ],
        ),
    )
)

# With an ECS option using dns.edns.ECSOption to form the option
q_list.append(
    (l, dns.message.make_query(n, t, options=[dns.edns.ECSOption("192.168.0.0", 20)]))
)

for (addr, q) in q_list:
    r = dns.query.udp(q, addr)
    if not r.options:
        print("No EDNS options returned")
    else:
        for o in r.options:
            print(o.otype.value, o.data)
    print()
