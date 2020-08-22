.. module:: dns.query
.. _query:

DNS Query Support
=================

The ``dns.query`` module is for sending messages to DNS servers, and
processing their responses.  If you want "stub resolver" behavior, then
you should use the higher level ``dns.resolver`` module; see :ref:`resolver`.

For UDP and TCP, the module provides a single "do everything" query
function, and also provides the send and receive halves of this function
individually for situations where more sophisticated I/O handling is
being used by the application.

UDP
---

.. autofunction:: dns.query.udp
.. autofunction:: dns.query.udp_with_fallback
.. autofunction:: dns.query.send_udp
.. autofunction:: dns.query.receive_udp

TCP
---

.. autofunction:: dns.query.tcp
.. autofunction:: dns.query.send_tcp
.. autofunction:: dns.query.receive_tcp

TLS
---

.. autofunction:: dns.query.tls

HTTPS
-----

.. autofunction:: dns.query.https

Zone Transfers
--------------

As of dnspython 2.1, :py:func:`dns.query.xfr` is deprecated.  Please use
:py:func:`dns.query.inbound_xfr` instead.

.. autoclass:: dns.query.UDPMode

.. autofunction:: dns.query.inbound_xfr

.. autofunction:: dns.query.xfr
