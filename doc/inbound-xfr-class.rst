.. _inbound-xfr-class:

The dns.xfr.Inbound Class and make_query() function
---------------------------------------------------

The ``Inbound`` class provides support for inbound DNS zone transfers, both
AXFR and IXFR.  I/O is handled in other classes.  When a message related
to the transfer arrives, the I/O code calls the ``process_message()`` method
which adds the content to the pending transaction.

.. autoclass:: dns.xfr.Inbound
   :members:

.. autofunction:: dns.xfr.make_query
