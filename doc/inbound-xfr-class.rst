.. _inbound-xfr-class:

The dns.xfr.Inbound Class and make_query() function
---------------------------------------------------

The ``Inbound`` class provides support for inbound DNS zone transfers,
both AXFR and IXFR.  It is invoked by I/O code, i.e.
:py:func:`dns.query.inbound_xfr` or
:py:func:`dns.asyncquery.inbound_xfr`.  When a message related to the
transfer arrives, the I/O code calls the ``process_message()`` method
which adds the content to the pending transaction.

The ``make_query()`` function is used to making the query message for
the query methods to use in more complex situations, e.g. with TSIG or
EDNS.

.. autoclass:: dns.xfr.Inbound
   :members:

.. autofunction:: dns.xfr.make_query
