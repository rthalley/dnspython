#!/usr/bin/env python3
#
# This is an example of sending DNS queries over TLS (DoT) with dnspython.

import dns.message
import dns.query
import dns.rdatatype


def main():
    where = "1.1.1.1"
    qname = "example.com."
    q = dns.message.make_query(qname, dns.rdatatype.A)
    r = dns.query.tls(q, where)
    for answer in r.answer:
        print(answer)

        # ... do more lookups


if __name__ == "__main__":
    main()
