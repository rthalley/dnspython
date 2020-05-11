.. module:: dns.name
.. _name:

DNS Names
=========

Objects of the dns.name.Name class represent an immutable domain name.
The representation is a tuple of labels, with each label being a ``bytes``
object in the DNS wire format.  Typically names are not created by
supplying the labels tuple directly, but rather by converting from DNS
text format or the DNS wire format.

Labels are in the same order as in the DNS textual form, e.g. the labels
value for ``www.dnspython.org.`` is ``(b'www', b'dnspython', b'org', b'')``.

Names may be *absolute* or *relative*.  Absolute names end in the root label,
which is an empty ``bytes``.  Relative names do not end in the root label.  To
convert a relative name to an absolute name requires specifying an *origin*.
Typically the origin is known by context.  Dnspython provides tools to
relativize and derelativize names.  It's a good idea not to mix relative
and absolute names, other than in the context of a zone.  Names encoded
in the DNS wire protocol are always absolute.  Dnspython's functions to
make names from text also default to an origin of the root name, and thus
to make a relative name using them you must specify an origin of None or
``dns.name.empty``.

Names are compared and ordered according to the rules of the DNS.  The
order is the DNSSEC canonical ordering.  Relative names always sort before
absolute names.

Names may also be compared according to the DNS tree hierarchy with
the ``fullcompare()`` method.  For example ```www.dnspython.org.`` is
a subdomain of ``dnspython.org.``.  See the method description for
full details.

.. toctree::

   name-class
   name-make
   name-dict
   name-helpers
   name-codecs
