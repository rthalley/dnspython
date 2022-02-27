.. _rdata-class:

======================
 DNS Rdata Base Class
======================

All Rdata objects are instances of some subclass of
``dns.rdata.Rdata``, and are immutable.  The Rdata factory functions
described in :ref:`rdata-make` will create objects which are instances
of the most appropriate subclass.  For example, a AAAA record will be
an instance of the ``dns.rdtypes.IN.AAAA`` class, but a record of
TYPE12345, which we don't know anything specific about, will be an
instance of ``dns.rdata.GenericRdata``.

Rdata of the same type and class are ordered.  For rdata that do not
contain domain names, or which contain absolute domain names, the
order is the same as the DNSSEC ordering.  For rdata containing at
least one relative name, that rdata will sort before any rdata with an
absolute name.  This makes comparison well defined (compared to
earlier versions of dnspython), but is a stop-gap measure for backwards
compatibility.  We want to disallow this type of comparison because it easily
leads to bugs.  Consider this rdataset::

    $ORIGIN example.
    name 300 IN NS a    ; 1
                NS a.   ; 2

In this case the record marked "2" sorts before the one marked "1"
when all the names are made absolute and the DNSSEC ordering is used.
But when relative comparisons are allowed, "1" sorts before "2".  This
isn't merely cosmetic, as code making a DNSSEC signature or computing
a zone checksum would get different answers for the same content
if it failed to make all names absolute before sorting.

Comparing relative rdata with absolute is thus deprecated and will be
removed in a future version of dnspython.  Setting
``dns.rdata._allow_relative_comparisons`` to ``True`` will allow the
future behavior to be tested with existing code.

.. autoclass:: dns.rdata.Rdata
   :members:
   :inherited-members:
