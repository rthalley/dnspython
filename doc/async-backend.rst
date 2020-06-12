module:: dns.asyncbackend
.. _async-backend:

Asynchronous Backend Functions
==============================

Dnspython has a "backend" for Trio, Curio, and asyncio which implements
the library-specific functionality needed by the generic asynchronous
DNS code.

Dnspython attempts to determine which backend is in use by "sniffing" for it
with the ``sniffio`` module if it is installed.  If sniffio is not available,
dnspython try to detect asyncio directly.

.. autofunction:: dns.asyncbackend.get_default_backend
.. autofunction:: dns.asyncbackend.set_default_backend
.. autofunction:: dns.asyncbackend.sniff
.. autofunction:: dns.asyncbackend.get_backend
