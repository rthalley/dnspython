.. module:: dns.asyncquery
.. _async_query:

DNS Query Support
=================

The ``dns.asyncquery`` module is for sending messages to DNS servers, and
processing their responses.  If you want "stub resolver" behavior, then
you should use the higher level ``dns.asyncresolver`` module; see
:ref:`async_resolver`.

For UDP and TCP, the module provides a single "do everything" query
function, and also provides the send and receive halves of this function
individually for situations where more sophisticated I/O handling is
being used by the application.

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

HTTPS
-----

.. autofunction:: dns.asyncquery.https


Zone Transfers
--------------

.. autofunction:: dns.asyncquery.inbound_xfr
