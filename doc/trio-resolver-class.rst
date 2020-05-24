.. _trio-resolver-class:

The dns.trio.resolver.Resolver Class
------------------------------------

The Trio resolver is a subclass of ``dns.resolver.Resolver`` and has the
same attributes.  The methods are similar, but I/O methods like ``resolve()``
are asynchronous.

.. autoclass:: dns.trio.resolver.Resolver
   :members:
