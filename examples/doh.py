#!/usr/bin/env python3
#
# This is an example of sending DNS queries over HTTPS (DoH) with dnspython.
import httpx

import dns.message
import dns.query
import dns.rdatatype


def main():
    where = "https://dns.google/dns-query"
    qname = "example.com."
    with httpx.Client() as client:
        q = dns.message.make_query(qname, dns.rdatatype.A)
        r = dns.query.https(q, where, session=client)
        for answer in r.answer:
            print(answer)

        # ... do more lookups


if __name__ == "__main__":
    main()
