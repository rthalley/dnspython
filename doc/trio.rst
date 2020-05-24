.. module:: dns.trio
.. _trio:

Trio Asynchronous I/O Support
=============================

The ``dns.trio.query`` module offers very similar APIs to those of
``dns.query``, only these versions are asynchronous and use Trio for
I/O.  There are no timeout parameters, as timeouts are expected to be
done in the Trio style with a cancellation scope.

The ``dns.trio.resolver`` module offers very similar APIs to those of
``dns.query``, only these versions are asynchronous and use Trio for
I/O.  There are no timeout parameters, as timeouts are expected to be
done in the Trio style with a cancellation scope.

.. toctree::

   trio-query
   trio-resolver
