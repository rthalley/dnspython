.. module:: dns.asyncquery
.. _async_query:

DNS Query Support
=================

The ``dns.asyncquery`` module is for sending messages to DNS servers, and
processing their responses.  If you want "stub resolver" behavior, then
you should use the higher level ``dns.asyncresolver`` module; see
:ref:`async_resolver`.

There is currently no support for zone transfers or DNS-over-HTTPS
using asynchronous I/O but we hope to offer this in the future.

UDP
---

.. autofunction:: dns.asyncquery.udp
.. autofunction:: dns.asyncquery.udp_with_fallback
.. autofunction:: dns.asyncquery.send_udp
.. autofunction:: dns.asyncquery.receive_udp

TCP
---

.. autofunction:: dns.asyncquery.tcp
.. autofunction:: dns.asyncquery.send_tcp
.. autofunction:: dns.asyncquery.receive_tcp

TLS
---

.. autofunction:: dns.asyncquery.tls
