# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import base64
import functools
import socket

import hypercorn.config
import hypercorn.trio
import quart
import quart_trio


def setup(server, connection_type):
    name = f"{__name__}-{connection_type.name}"
    app = quart_trio.QuartTrio(name)
    app.logger.handlers = []

    @app.route("/dns-query", methods=["GET", "POST"])
    async def dns_query():
        if quart.request.method == "POST":
            wire = await quart.request.body
        else:
            encoded = quart.request.args["dns"]
            remainder = len(encoded) % 4
            if remainder != 0:
                encoded += "=" * (4 - remainder)
            wire = base64.urlsafe_b64decode(encoded)
        for body in server.handle_wire(
            wire,
            quart.request.remote_addr,
            quart.request.server,
            connection_type,
        ):
            if body is not None:
                return quart.Response(body, mimetype="application/dns-message")
            else:
                return quart.Response(status=500)

    return app


def make_server(server, sock, connection_type, tls_chain, tls_key):
    doh_app = setup(server, connection_type)
    hconfig = hypercorn.config.Config()
    fd = sock.fileno()
    if sock.type == socket.SOCK_STREAM:
        # We put http/1.1 in the ALPN as we don't mind, but DoH is
        # supposed to be H2 officially.
        hconfig.alpn_protocols = ["h2", "http/1.1"]
        hconfig.bind = [f"fd://{fd}"]
        hconfig.quic_bind = []
    else:
        hconfig.alpn_protocols = ["h3"]
        # We should be able to pass bind=[], but that triggers a bug in
        # hypercorn.  So, create a dummy socket and bind to it.
        tmp_sock = socket.create_server(("127.0.0.1", 0))
        hconfig.bind = [f"fd://{tmp_sock.fileno()}"]
        tmp_sock.detach()
        hconfig.quic_bind = [f"fd://{fd}"]
    sock.detach()
    hconfig.certfile = tls_chain
    hconfig.keyfile = tls_key
    hconfig.accesslog = None
    hconfig.errorlog = None
    return functools.partial(hypercorn.trio.serve, doh_app, hconfig)
