
import dns.edns
import dns.message
import dns.query

# This example demonstrates how to use the EDNS client subnet option

ADDRESS = '0.0.0.0'  # replace this with the address you want to check
PREFIX = 0  # replace this with a prefix length (typically 24 for IPv4)

ecs = dns.edns.ECSOption(ADDRESS, PREFIX)
q = dns.message.make_query('www.google.com', 'A', use_edns=0, options=[ecs])
r = dns.query.udp(q, '8.8.8.8')
print(r)

