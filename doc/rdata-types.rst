.. _rdata-types:

Rdata classes and types
-----------------------

Sets of typed data can be associated with a given name.  A single typed
datum is called an *rdata*.  The type of an rdata is specified by its
*rdataclass* and *rdatatype*.  The class is almost always `IN`, the Internet
class, and may often be omitted in the dnspython APIs.

The ``dns.rdataclass`` module provides constants for each defined
rdata class, as well as some helpful functions.  The ``dns.rdatatype``
module does the same for rdata types.  Examples of the constants are::

  dns.rdataclass.IN
  dns.rdatatype.AAAA

.. automodule:: dns.rdataclass
   :members:

.. automodule:: dns.rdatatype
   :members:

.. toctree::
   rdataclass-list
   rdatatype-list
