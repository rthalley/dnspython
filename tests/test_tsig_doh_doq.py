# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# TSIG over DoH, DoH3, and DoQ: the response must be validated against the MAC
# of the signed query, and a response without a TSIG must be rejected.

import asyncio
try:
    import ssl
    have_ssl = True
except ImportError:
    import dns._no_ssl as ssl  # pyright: ignore
    have_ssl = False

import pytest

import dns.asyncbackend
import dns.asyncquery
import dns.exception
import dns.message
import dns.query
import dns.tsigkeyring

from .util import here

try:
    from .nanonameserver import ConnectionType, Server, have_doh, have_doq

    _nanonameserver_available = True
except ImportError:
    _nanonameserver_available = False
    have_doh = False
    have_doq = False

    class Server:  # type: ignore
        pass


keyring = dns.tsigkeyring.from_text({"name": "tDz6cfXXGtNivRpQ98hr6A=="})
ca = here("tls/ca.crt")
ca_context = ssl.create_default_context(cafile=ca)


class SignedServer(Server):
    def handle(self, request):
        return dns.message.make_response(request.message)


class UnsignedServer(Server):
    def handle(self, request):
        response = dns.message.make_response(request.message)
        response.keyring = None
        response.tsig = None
        return response


def make_signed_query():
    q = dns.message.make_query("www.example.", "A")
    q.use_tsig(keyring=keyring, keyname="name")
    return q


def doq(server, q):
    port = server.get_address(ConnectionType.DOQ)[1]
    return dns.query.quic(q, "127.0.0.1", port=port, verify=ca)


def async_doq(server, q):
    port = server.get_address(ConnectionType.DOQ)[1]
    dns.asyncbackend.set_default_backend("asyncio")
    return asyncio.run(dns.asyncquery.quic(q, "127.0.0.1", port=port, verify=ca))


def doh(server, q):
    port = server.get_address(ConnectionType.DOH)[1]
    return dns.query.https(q, f"https://127.0.0.1:{port}/dns-query", verify=ca_context)


def async_doh(server, q):
    port = server.get_address(ConnectionType.DOH)[1]
    dns.asyncbackend.set_default_backend("asyncio")
    return asyncio.run(
        dns.asyncquery.https(q, f"https://127.0.0.1:{port}/dns-query", verify=ca_context)
    )


def doh3(server, q):
    port = server.get_address(ConnectionType.DOH3)[1]
    return dns.query.https(
        q,
        f"https://127.0.0.1:{port}/dns-query",
        verify=ca,
        http_version=dns.query.HTTPVersion.H3,
    )


def async_doh3(server, q):
    port = server.get_address(ConnectionType.DOH3)[1]
    dns.asyncbackend.set_default_backend("asyncio")
    return asyncio.run(
        dns.asyncquery.https(
            q,
            f"https://127.0.0.1:{port}/dns-query",
            verify=ca,
            http_version=dns.asyncquery.HTTPVersion.H3,
        )
    )


transports = [
    pytest.param(doq, marks=pytest.mark.skipif(not have_doq, reason="requires DoQ")),
    pytest.param(
        async_doq, marks=pytest.mark.skipif(not have_doq, reason="requires DoQ")
    ),
    pytest.param(doh, marks=pytest.mark.skipif(not have_doh, reason="requires DoH")),
    pytest.param(
        async_doh, marks=pytest.mark.skipif(not have_doh, reason="requires DoH")
    ),
    pytest.param(
        doh3,
        marks=pytest.mark.skipif(not (have_doh and have_doq), reason="requires DoH3"),
    ),
    pytest.param(
        async_doh3,
        marks=pytest.mark.skipif(not (have_doh and have_doq), reason="requires DoH3"),
    ),
]


@pytest.mark.skipif(not _nanonameserver_available or not have_ssl,
                    reason="requires nanonameserver and ssl")
@pytest.mark.parametrize("query_function", transports)
def test_signed_response(query_function):
    with SignedServer(keyring=keyring) as server:
        r = query_function(server, make_signed_query())
        assert r.had_tsig


@pytest.mark.skipif(not _nanonameserver_available or not have_ssl,
                    reason="requires nanonameserver and ssl")
@pytest.mark.parametrize("query_function", transports)
def test_unsigned_response(query_function):
    with UnsignedServer(keyring=keyring) as server:
        with pytest.raises(dns.exception.FormError):
            query_function(server, make_signed_query())
