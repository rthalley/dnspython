.. _async:

Asynchronous I/O Support
========================

The ``dns.asyncquery`` and ``dns.asyncresolver`` modules offer
asynchronous APIs equivalent to those of ``dns.query`` and
``dns.resolver``.

Dnspython presents a uniform API, but offers three different backend
implementations, to support the Trio, Curio, and asyncio libraries.
Dnspython attempts to detect which library is in use by using the
``sniffio`` library if it is available.  It's also possible to
explicitly select a "backend" library, or to pass a backend to
a particular call, allowing for use in mixed library situations.

.. toctree::

   async-query
   async-resolver
   async-backend
