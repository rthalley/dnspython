.. _resolver-class:

The dns.resolver.Resolver and dns.resolver.Answer Classes
---------------------------------------------------------

.. autoclass:: dns.resolver.Resolver
   :members:

   .. attribute:: domain

      A ``dns.name.Name``, the domain of this host.

   .. more attributes here!      

.. autoclass:: dns.resolver.Answer
   :members:

   .. attribute:: qname

      A ``dns.name.Name``, the query name.

   .. attribute:: rdclass

      An ``int``, the query class.

   .. attribute:: rdtype

      An ``int``, the query type.

   .. attribute:: response

      A ``dns.message.Message``, the response message.

   .. attribute:: rrset

      A ``dns.rrset.RRset`` or ``None``, the answer RRset.

   .. attribute:: expiration

      A ``float``, the time when the answer expires.

   .. attribute:: canonical_name

      A ``dns.name.Name``, the canonical name of the query name,
      i.e. the owner name of the answer RRset after any CNAME and DNAME
      chaining.
