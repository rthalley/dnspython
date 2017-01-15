.. _message-edns:

Message EDNS Options
--------------------

EDNS allows for larger messages and also provides an extension
mechanism for the protocol.  EDNS *options* are typed data, and are
treated much like Rdata.  For example, if dnsython encouters the EDNS
``ECS`` option code when parsing a DNS wire format message, it
will create a ``dns.edns.ECSOption`` object to represent it.

.. autodata:: dns.edns.NSID
.. autodata:: dns.edns.DAU
.. autodata:: dns.edns.DHU
.. autodata:: dns.edns.N3U
.. autodata:: dns.edns.ECS
.. autodata:: dns.edns.EXPIRE
.. autodata:: dns.edns.COOKIE
.. autodata:: dns.edns.KEEPALIVE
.. autodata:: dns.edns.PADDING
.. autodata:: dns.edns.CHAIN

.. autoclass:: dns.edns.Option
   :members:

.. autoclass:: dns.edns.GenericOption
   :members:

.. autoclass:: dns.edns.ECSOption
   :members:
   
.. autofunction:: dns.edns.get_option_class
.. autofunction:: dns.edns.option_from_wire
