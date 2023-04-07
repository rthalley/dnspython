#!/usr/bin/env python3

# Using Discovery of Designated Resolvers (synchronous I/O)

import dns.resolver

res = dns.resolver.Resolver(configure=False)
res.nameservers = ["1.1.1.1"]
# Invoke try_ddr() to attempt to upgrade the connection via DDR
res.try_ddr()
# Do a sample resolution
for rr in res.resolve("www.google.com", "A"):
    print(rr.address)
# Note that the nameservers have been upgraded
print(res.nameservers)


# Using Discovery of Designated Resolvers (asynchronous I/O)

# We show using asyncio, but if you comment out asyncio lines
# and uncomment the trio lines, it will work with trio too.

import asyncio

# import trio

import dns.asyncresolver


async def amain():
    res = dns.asyncresolver.Resolver(configure=False)
    res.nameservers = ["8.8.8.8"]
    await res.try_ddr()

    for rr in await res.resolve("www.google.com", "A"):
        print(rr.address)

    print(res.nameservers)


asyncio.run(amain())
# trio.run(amain)
