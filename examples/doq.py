import asyncio
import threading

import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.query
import dns.quic
import dns.rdatatype

try:
    import trio

    have_trio = True
except ImportError:
    have_trio = False

# This demo assumes you have the aioquic example doq_server.py running on localhost
# on port 4784 on localhost.
peer_address = "127.0.0.1"
peer_port = 4784
query_name = "www.dnspython.org"
tls_verify_mode = False


def squery(rdtype="A", connection=None):
    q = dns.message.make_query(query_name, rdtype)
    r = dns.query.quic(
        q, peer_address, port=peer_port, connection=connection, verify=tls_verify_mode
    )
    print(r)


def srun():
    squery()


def smultirun():
    with dns.quic.SyncQuicManager(verify_mode=tls_verify_mode) as manager:
        connection = manager.connect(peer_address, peer_port)
        t1 = threading.Thread(target=squery, args=["A", connection])
        t1.start()
        t2 = threading.Thread(target=squery, args=["AAAA", connection])
        t2.start()
        t1.join()
        t2.join()


async def aquery(rdtype="A", connection=None):
    q = dns.message.make_query(query_name, rdtype)
    r = await dns.asyncquery.quic(
        q, peer_address, port=peer_port, connection=connection, verify=tls_verify_mode
    )
    print(r)


def arun():
    asyncio.run(aquery())


async def amulti():
    async with dns.quic.AsyncioQuicManager(verify_mode=tls_verify_mode) as manager:
        connection = manager.connect(peer_address, peer_port)
        t1 = asyncio.Task(aquery("A", connection))
        t2 = asyncio.Task(aquery("AAAA", connection))
        await t1
        await t2


def amultirun():
    asyncio.run(amulti())


if have_trio:

    def trun():
        trio.run(aquery)

    async def tmulti():
        async with trio.open_nursery() as nursery:
            async with dns.quic.TrioQuicManager(
                nursery, verify_mode=tls_verify_mode
            ) as manager:
                async with trio.open_nursery() as query_nursery:
                    # We run queries in a separate nursery so we can demonstrate
                    # waiting for them all to exit without waiting for the manager to
                    # exit as well.
                    connection = manager.connect(peer_address, peer_port)
                    query_nursery.start_soon(aquery, "A", connection)
                    query_nursery.start_soon(aquery, "AAAA", connection)

    def tmultirun():
        trio.run(tmulti)


def main():
    print("*** Single Queries ***")
    print("--- Sync ---")
    srun()
    print("--- Asyncio ---")
    dns.asyncbackend.set_default_backend("asyncio")
    arun()
    if have_trio:
        print("--- Trio ---")
        dns.asyncbackend.set_default_backend("trio")
        trun()
    print("*** Multi-connection Queries ***")
    print("--- Sync ---")
    smultirun()
    print("--- Asyncio ---")
    dns.asyncbackend.set_default_backend("asyncio")
    amultirun()
    if have_trio:
        print("--- Trio ---")
        dns.asyncbackend.set_default_backend("trio")
        tmultirun()


if __name__ == "__main__":
    main()
