.. _message-class:

The dns.message.Message Class
-----------------------------

.. autoclass:: dns.message.Message
   :members:

   .. attribute:: id

      An ``int``, the query id; the default is a randomly chosen id.

   .. attribute:: flags

      An ``int``, the DNS flags of the message.

   .. attribute:: question

      The question section, a list of ``dns.rrset.RRset`` objects.

   .. attribute:: answer

      The answer section, a list of ``dns.rrset.RRset`` objects.

   .. attribute:: authority

      The authority section, a list of ``dns.rrset.RRset`` objects.

   .. attribute:: additional

      The additional section, a list of ``dns.rrset.RRset`` objects.

   .. attribute:: edns

      An ``int``, the EDNS level to use.  The default is -1, no EDNS.

   .. attribute:: ednsflags

      An ``int``, the EDNS flags.
      
   .. attribute:: payload

      An ``int``, the EDNS payload size.  The default is 0.

   .. attribute:: options

      The EDNS options, a list of ``dns.edns.Option`` objects.  The default
      is the empty list.

   .. attribute:: request_payload

      The associated request's EDNS payload size.  This field is meaningful
      in response messages, and if set to a non-zero value, will limit
      the size of the response to the specified size.  The default is 0,
      which means "use the default limit" which is currently 65535.

   .. attribute:: keyring

      The TSIG keyring to use.  The default is `None`.  A TSIG keyring
      is a dictionary mapping from TSIG key name, a ``dns.name.Name``, to
      a TSIG secret, a ``binary``.

   .. attribute:: keyname

      The TSIG keyname to use, a ``dns.name.Name``.  The default is ``None``.

   .. attribute:: keyalgorithm

      A ``dns.name.Name``, the TSIG algorithm to use.  Defaults to
      ``dns.tsig.default_algorithm``.  Constants for TSIG algorithms are
      defined the in ``dns.tsig`` module.

   .. attribute:: request_mac

      A ``binary``, the TSIG MAC of the request message associated with
      this message; used when validating TSIG signatures.

   .. attribute:: fudge

      An ``int``, the TSIG time fudge.  The default is 300 seconds.

   .. attribute:: original_id

      An ``int``, the TSIG original id; defaults to the message's id.
      
   .. attribute:: tsig_error

      An ``int``, the TSIG error code.  The default is 0.

   .. attribute:: other_data

      A ``binary``, the TSIG "other data".  The default is the empty
      ``binary``.

   .. attribute:: mac

      A ``binary``, the TSIG MAC for this message.

   .. attribute:: xfr

      A ``bool``.  This attribute is true when the message being used
      for the results of a DNS zone transfer.  The default is ``False``.

   .. attribute:: origin

      A ``dns.name.Name``.  The origin of the zone in messages which are
      used for zone transfers or for DNS dynamic updates.  The default
      is ``None``.

   .. attribute:: tsig_ctx

      An ``hmac.HMAC``, the TSIG signature context associated with this
      message.  The default is ``None``.

   .. attribute:: had_tsig

      A ``bool``, which is ``True`` if the message had a TSIG signature
      when it was decoded from wire format.

   .. attribute:: multi

      A ``bool``, which is ``True`` if this message is part of a
      multi-message sequence.  The default is ``False``.
      This attribute is used when validating TSIG signatures
      on messages which are part of a zone transfer.

   .. attribute:: first

      A ``bool``, which is ``True`` if this message is stand-alone,
      or the first of a multi-message sequence.  The default is ``True``.
      This variable is used when validating TSIG signatures
      on messages which are part of a zone transfer.

   .. attribute:: index

      A ``dict``, an index of RRsets in the message.  The index key is
      ``(section, name, rdclass, rdtype, covers, deleting)``.  The default
      is ``{}``.  Indexing improves the performance of finding RRsets.
      Indexing can be disabled by setting the index to ``None``.

The following constants may be used to specify sections in the
``find_rrset()`` and ``get_rrset()`` methods:

.. autodata:: dns.message.QUESTION
.. autodata:: dns.message.ANSWER
.. autodata:: dns.message.AUTHORITY
.. autodata:: dns.message.ADDITIONAL
