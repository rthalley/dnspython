.. module:: dns.trio.query
.. _trio-query:

DNS Query Support
=================

The ``dns.trio.query`` module is for sending messages to DNS servers, and
processing their responses.  If you want "stub resolver" behavior, then
you should use the higher level ``dns.trio.resolver`` module; see
:ref:`trio_resolver`.

There is currently no support for zone transfers or DNS-over-HTTPS
using Trio, but we hope to offer this in the future.

UDP
---

.. autofunction:: dns.trio.query.udp
.. autofunction:: dns.trio.query.udp_with_fallback
.. autofunction:: dns.trio.query.send_udp
.. autofunction:: dns.trio.query.receive_udp

Streams (TCP and TLS)
---------------------

.. autofunction:: dns.trio.query.stream
.. autofunction:: dns.trio.query.send_stream
.. autofunction:: dns.trio.query.receive_stream
