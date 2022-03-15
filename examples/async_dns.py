import sys

import trio

import dns.message
import dns.asyncquery
import dns.asyncresolver


async def main():
    if len(sys.argv) > 1:
        host = sys.argv[0]
    else:
        host = "www.dnspython.org"
    q = dns.message.make_query(host, "A")
    r = await dns.asyncquery.udp(q, "8.8.8.8")
    print(r)
    q = dns.message.make_query(host, "A")
    r = await dns.asyncquery.tcp(q, "8.8.8.8")
    print(r)
    q = dns.message.make_query(host, "A")
    r = await dns.asyncquery.tls(q, "8.8.8.8")
    print(r)
    a = await dns.asyncresolver.resolve(host, "A")
    print(a.response)
    zn = await dns.asyncresolver.zone_for_name(host)
    print(zn)


if __name__ == "__main__":
    trio.run(main)
