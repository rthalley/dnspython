.. _rdata-set-classes:

Rdataset, RRset and Node Classes
================================

An ``Rdataset`` is a set of ``Rdata`` objects which all have the same
rdatatype, rdataclass, and covered type.  ``Rdatasets`` also have a
``ttl`` (DNS time-to-live) field.  Rdatasets support the normal Python
set API, but are also ordered.

An ``RRset`` is a subclass of ``Rdataset`` that also has an owner
name, i.e. a ``dns.name.Name`` that says where in the DNS tree this
set is located.

A ``Node`` is a set of ``Rdataset`` objects, the Rdatasets being
interpreted as at the same place (i.e. same owner name) int the DNS
tree.  Nodes are primarily used in ``Zone`` objects.

.. autoclass:: dns.rdataset.Rdataset
   :members:

.. autoclass:: dns.rrset.RRset
   :members:

.. autoclass:: dns.node.Node
   :members:
