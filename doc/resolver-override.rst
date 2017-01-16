.. _resolver-override:

Overriding the System Resolver
------------------------------

Sometimes it can be useful to make all of Python use dnspython's resolver
rather than the default functionality in the ``socket`` module.  Dnspython
can redefine the entires in the socket module to point at its own code, and
it can also restore them back to the regular Python defaults.

.. autofunction:: dns.resolver.override_system_resolver
.. autofunction:: dns.resolver.restore_system_resolver
