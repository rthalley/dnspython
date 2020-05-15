.. _resolver-class:

The dns.resolver.Resolver and dns.resolver.Answer Classes
---------------------------------------------------------

.. autoclass:: dns.resolver.Resolver
   :members:

   .. attribute:: domain

      A ``dns.name.Name``, the domain of this host.

   .. attribute:: nameservers

      A ``list`` of ``str``, each item containing an IPv4 or IPv6 address.

   .. attribute:: search

      A ``list`` of dns.name.Name objects.  If the query name is a
      relative name, the resolver will construct absolute query names
      to try by appending values from the search list.

   .. attribute:: use_search_by_default

      A ``bool``, specifes whether or not ``resolve()`` uses the
      search list configured in the system's resolver configuration
      when the ``search`` parameter to ``resolve()`` is ``None``.  The
      default is ``False``.

   .. attribute:: port

      An ``int``, the default DNS port to send to if not overriden by
      *nameserver_ports*.  The default value is 53.

   .. attribute:: nameserver_ports

      A ``dict`` mapping an IPv4 or IPv6 address ``str`` to an ``int``.
      This specifies the port to use when sending to a nameserver.  If
      a port is not defined for an address, the value of the *port*
      attribute will be used.

   .. attribute:: timeout

      A ``float``, the number of seconds to wait for a response from
      a server.

   .. attribute:: lifetime

      A ``float``, the number of seconds to spend trying to get an
      answer to the question.  If the lifetime expires a
      ``dns.exception.Timeout`` exception will be raised.

   .. attribute::  cache

      An object implementing the caching protocol, e.g. a
      ``dns.resolver.Cache`` or a ``dns.resolver.LRUCache``.  The default
      is ``None``, in which case there is no local caching.
       
   .. attribute:: retry_servfail

      A ``bool``.  Should we retry a nameserver if it says ``SERVFAIL``?
      The default is ``False``.

   .. attribute:: keyring

      A ``dict``, the TSIG keyring to use.  If a *keyring* is
      specified but a *keyname* is not, then the key used will be
      the first key in the *keyring*.  Note that the order of keys
      in a dictionary is not defined, so applications should supply
      a keyname when a keyring is used, unless they know the keyring
      contains only one key.

   .. attribute:: keyname

      A ``dns.name.Name`` or ``None``, the name of the TSIG key to
      use; defaults to ``None``. The key must be defined in the
      keyring.
        
   .. attribute:: keyalgorithm

      A ``dns.name.Name`` or ``str``, the TSIG algorithm to use.

   .. attribute:: edns

      An ``int``, the EDNS level to use.  Specifying
      ``None``, ``False``, or ``-1`` means "do not use EDNS", and in
      this case the other parameters are ignored.  Specifying
      ``True`` is equivalent to specifying 0, i.e. "use EDNS0".

   .. attribute:: ednsflags

      An ``int``, the EDNS flag values.

   .. attribute:: payload

      An ``int``, is the EDNS sender's payload field, which is the
      maximum size of UDP datagram the sender can handle.  I.e. how big
      a response to this message can be.

   .. attribute:: flags

      An ``int`` or ``None``, the message flags to use.  If ``None``,
      then the default flags as set by the ``dns.message.Message``
      constructor will be used.


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
