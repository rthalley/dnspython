.. _async:

Asynchronous I/O Support
========================

The :py:mod:`dns.asyncquery` and :py:mod:`dns.asyncresolver` modules offer
asynchronous APIs equivalent to those of :py:mod:`dns.query` and
:py:mod:`dns.resolver`.

Dnspython presents a uniform API, but offers two different backend
implementations, to support the Trio and asyncio libraries.
Dnspython attempts to detect which library is in use by using the
``sniffio`` library if it is available.  It's also possible to
explicitly select a "backend" library, or to pass a backend to
a particular call, allowing for use in mixed library situations.

.. toctree::

   async-query
   async-resolver
   async-backend
