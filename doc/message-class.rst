.. _message-class:

The dns.message.Message Class
-----------------------------

This is the base class for all messages, and the class used for any
DNS opcodes that do not have a more specific class.

.. _message-indexing:

RRset lookup and section mutation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, :py:meth:`~dns.message.Message.find_rrset` and
:py:meth:`~dns.message.Message.get_rrset` look up RRsets in an index.
Use either method with ``create=True`` to add an RRset while keeping the
index consistent.  Once an RRset has been found, records can be added to it
without appending another RRset to the section.

Direct changes to the section lists, such as appending, removing, or
replacing RRsets, do not update the index.  Changing an RRset's indexed
attributes (name, class, type, covered type, or deleting class) can also
make the index inconsistent.  A subsequent lookup may miss an RRset in a
section or return an RRset that has been removed.

If you need to make such changes directly, disable indexing by setting
``message.index = None``.  The lookup methods will then scan the requested
section instead of using the index.  For example::

    import dns.message
    import dns.rrset

    message = dns.message.Message()
    message.index = None
    rrset = dns.rrset.from_text("www.example.", 300, "IN", "A", "192.0.2.1")
    message.answer.append(rrset)
    assert message.get_rrset(
        message.answer, rrset.name, rrset.rdclass, rrset.rdtype
    ) is rrset

Disabling indexing also works after a message has been created or parsed.
Do not set ``index`` back to an empty dictionary on a populated message:
that does not rebuild the index and makes existing RRsets invisible to
indexed lookups.  Serializing a message with
:py:meth:`~dns.message.Message.to_wire` uses the section lists, not the index.

.. autoclass:: dns.message.Message
   :members:

   .. attribute:: id

      An ``int``, the query id; the default is a randomly chosen id.

   .. attribute:: flags

      An ``int``, the DNS flags of the message.

   .. attribute:: sections

      A list of lists of :py:class:`dns.rrset.RRset` objects.

   .. attribute:: edns

      An ``int``, the EDNS level to use.  The default is -1, no EDNS.

   .. attribute:: ednsflags

      An ``int``, the EDNS flags.

   .. attribute:: payload

      An ``int``, the EDNS payload size.  The default is 0.

   .. attribute:: options

      The EDNS options, a list of :py:class:`dns.edns.Option` objects.  The default
      is the empty list.

   .. attribute:: request_payload

      The associated request's EDNS payload size.  This field is meaningful
      in response messages, and if set to a non-zero value, will limit
      the size of the response to the specified size.  The default is 0,
      which means "use the default limit" which is currently 65535.

   .. attribute:: keyring

      A ``dns.tsig.Key``, the TSIG key.  The default is None.

   .. attribute:: keyname

      The TSIG keyname to use, a :py:class:`dns.name.Name`.  The default is ``None``.

   .. attribute:: keyalgorithm

      A :py:class:`dns.name.Name`, the TSIG algorithm to use.  Defaults to
      ``dns.tsig.default_algorithm``.  Constants for TSIG algorithms are
      defined the in ``dns.tsig`` module.

   .. attribute:: request_mac

      A ``bytes``, the TSIG MAC of the request message associated with
      this message; used when validating TSIG signatures.

   .. attribute:: fudge

      An ``int``, the TSIG time fudge.  The default is 300 seconds.

   .. attribute:: original_id

      An ``int``, the TSIG original id; defaults to the message's id.

   .. attribute:: tsig_error

      An ``int``, the TSIG error code.  The default is 0.

   .. attribute:: other_data

      A ``bytes``, the TSIG "other data".  The default is the empty
      ``bytes``.

   .. attribute:: mac

      A ``bytes``, the TSIG MAC for this message.

   .. attribute:: xfr

      A ``bool``.  This attribute is true when the message being used
      for the results of a DNS zone transfer.  The default is ``False``.

   .. attribute:: origin

      A :py:class:`dns.name.Name`.  The origin of the zone in messages which are
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
      Indexing can be disabled by setting the index to ``None``.  See
      :ref:`message-indexing` for the constraints on direct section mutation.

   .. attribute:: wire

      A ``bytes`` or ``None``, the encoded wire format data used to create this
      message with :py:func:`dns.message.from_wire` or the output most recently generated by
      ``to_wire()``.

.. autoclass:: dns.message.MessageStyle
   :members:
   :inherited-members:

The following constants may be used to specify sections in the
``find_rrset()`` and ``get_rrset()`` methods:

.. autodata:: dns.message.QUESTION
.. autodata:: dns.message.ANSWER
.. autodata:: dns.message.AUTHORITY
.. autodata:: dns.message.ADDITIONAL
