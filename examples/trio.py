
import sys
import trio

import dns.message
import dns.trio.query

async def main():
    if len(sys.argv) > 1:
        host = sys.argv[0]
    else:
        host = 'www.dnspython.org'
    q = dns.message.make_query(host, 'A')
    r = await dns.trio.query.udp(q, '8.8.8.8')
    print(r)
    q = dns.message.make_query(host, 'A')
    r = await dns.trio.query.stream(q, '8.8.8.8')
    print(r)
    q = dns.message.make_query(host, 'A')
    r = await dns.trio.query.stream(q, '8.8.8.8', tls=True)
    print(r)

if __name__ == '__main__':
    trio.run(main)
