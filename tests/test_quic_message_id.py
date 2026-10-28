# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# DoQ and DoH3 queries are sent with a message id of 0 (RFC 9250 section 4.2.1),
# but the caller's message must keep its id, as e.g. the resolver sends the same
# message to its other nameservers, and over UDP the id is anti-spoofing entropy.

import asyncio
import socket

import pytest

import dns.asyncbackend
import dns.asyncquery
import dns.entropy
import dns.exception
import dns.message
import dns.nameserver
import dns.query
import dns.rcode
import dns.resolver

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

    class ConnectionType:  # type: ignore
        DOQ = 5
        DOH3 = 6


ca = here("tls/ca.crt")
QUERY_ID = 4321


class RecordingServer(Server):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ids = []

    def handle(self, request):
        self.ids.append((request.connection_type, request.message.id))
        r = dns.message.make_response(request.message)
        if request.connection_type in (ConnectionType.DOQ, ConnectionType.DOH3):
            r.set_rcode(dns.rcode.SERVFAIL)
        else:
            r.set_rcode(dns.rcode.NXDOMAIN)
        return r


def make_query():
    q = dns.message.make_query("www.example.", "A")
    q.id = QUERY_ID
    return q


def doq(port, q, timeout=None):
    return dns.query.quic(q, "127.0.0.1", port=port, verify=ca, timeout=timeout)


def async_doq(port, q, timeout=None):
    dns.asyncbackend.set_default_backend("asyncio")
    return asyncio.run(
        dns.asyncquery.quic(q, "127.0.0.1", port=port, verify=ca, timeout=timeout)
    )


def doh3(port, q, timeout=None):
    return dns.query.https(
        q,
        f"https://127.0.0.1:{port}/dns-query",
        timeout=timeout,
        verify=ca,
        http_version=dns.query.HTTPVersion.H3,
    )


def async_doh3(port, q, timeout=None):
    dns.asyncbackend.set_default_backend("asyncio")
    return asyncio.run(
        dns.asyncquery.https(
            q,
            f"https://127.0.0.1:{port}/dns-query",
            timeout=timeout,
            verify=ca,
            http_version=dns.asyncquery.HTTPVersion.H3,
        )
    )


have_doh3 = have_doh and have_doq
transports = [
    pytest.param(
        doq,
        ConnectionType.DOQ,
        marks=pytest.mark.skipif(not have_doq, reason="requires DoQ"),
    ),
    pytest.param(
        async_doq,
        ConnectionType.DOQ,
        marks=pytest.mark.skipif(not have_doq, reason="requires DoQ"),
    ),
    pytest.param(
        doh3,
        ConnectionType.DOH3,
        marks=pytest.mark.skipif(not have_doh3, reason="requires DoH3"),
    ),
    pytest.param(
        async_doh3,
        ConnectionType.DOH3,
        marks=pytest.mark.skipif(not have_doh3, reason="requires DoH3"),
    ),
]


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
@pytest.mark.parametrize("query_function,connection_type", transports)
def test_query_id_is_kept(query_function, connection_type):
    with RecordingServer() as server:
        port = server.get_address(connection_type)[1]
        q = make_query()
        r = query_function(port, q)
        assert server.ids == [(connection_type, 0)]
        assert q.id == QUERY_ID
        assert r.id == QUERY_ID
        assert q.is_response(r)


class NonzeroIdServer(Server):
    def handle(self, request):
        r = dns.message.make_response(request.message)
        r.id = QUERY_ID
        return r


class WrongQuestionServer(Server):
    def handle(self, request):
        return dns.message.make_response(
            dns.message.make_query("other.example.", "A", id=0)
        )


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
@pytest.mark.parametrize("server_class", [NonzeroIdServer, WrongQuestionServer])
@pytest.mark.parametrize("query_function,connection_type", transports)
def test_bad_response(query_function, connection_type, server_class):
    with server_class() as server:
        port = server.get_address(connection_type)[1]
        with pytest.raises(dns.query.BadResponse):
            query_function(port, make_query())


@pytest.mark.parametrize("query_function,connection_type", transports)
def test_query_id_is_kept_on_failure(query_function, connection_type):
    # Nothing answers on this port, so the query times out.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        q = make_query()
        with pytest.raises(dns.exception.Timeout):
            query_function(port, q, timeout=0.2)
        assert q.id == QUERY_ID


@pytest.mark.skipif(not (_nanonameserver_available and have_doq), reason="requires DoQ")
def test_resolver_udp_after_doq(monkeypatch):
    monkeypatch.setattr(dns.entropy, "random_16", lambda: QUERY_ID)
    with RecordingServer() as server:
        res = dns.resolver.Resolver(configure=False)
        res.cache = None
        res.nameservers = [
            dns.nameserver.DoQNameserver(
                "127.0.0.1", server.get_address(ConnectionType.DOQ)[1], verify=ca
            ),
            dns.nameserver.Do53Nameserver(
                "127.0.0.1", server.get_address(ConnectionType.UDP)[1]
            ),
        ]
        with pytest.raises(dns.resolver.NXDOMAIN):
            res.resolve("www.example.", "A")
        # The DoQ query has id 0, and the UDP query after the DoQ SERVFAIL must
        # still have the id of the request.
        assert server.ids == [(ConnectionType.DOQ, 0), (ConnectionType.UDP, QUERY_ID)]
