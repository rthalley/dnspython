.. _rdata-class:

DNS Rdata Base Class
====================

All Rdata objects are instances of some subclass of
``dns.rdata.Rdata``, and are immutable.  The Rdata factory functions
described in :ref:`rdata-make` will create objects which are instances
of the most appropriate subclass.  For example, a AAAA record will be
an instance of the ``dns.rdtypes.IN.AAAA`` class, but a record of
TYPE12345, which we don't know anything specific about, will be an
instance of ``dns.rdata.GenericRdata``.

.. autoclass:: dns.rdata.Rdata
   :members:
