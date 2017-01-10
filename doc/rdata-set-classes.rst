.. _rdata-set-classes:

Rdataset and RRset Classes
==========================

An ``Rdataset`` is a set of ``Rdata`` objects which all have the same
rdatatype, rdataclass, and covered type.  ``Rdatasets`` also have a
``ttl`` (DNS time-to-live) field.  Rdatasets support the normal Python
set API, but are also ordered.

An ``RRset`` is a subclass of ``Rdataset`` that also has an owner
name, i.e. a ``dns.name.Name`` that says where in the DNS tree this
set is located.

.. autoclass:: dns.rdataset.Rdataset
   :members:

.. autoclass:: dns.rrset.RRset
   :members:
