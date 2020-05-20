.. _rdata:

DNS Rdata
=========

An Rdata is typed data in one of the known DNS datatypes, for example
type ``A``, the IPv4 address of a host or type ``MX``, how to route
mail.  Unlike like the DNS RFC concept of RR, an Rdata is not bound to
an owner name.  Rdata is immutable.

Rdata of the same type can be grouped into an unnamed set, an
Rdataset, or into a named set, an RRset.

.. toctree::

   rdata-types
   rdata-class
   rdata-make
   rdata-subclasses
   rdata-set-classes
   rdata-set-make
