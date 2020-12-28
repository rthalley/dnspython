.. _message-query:

The dns.message.QueryMessage Class
----------------------------------

The ``dns.message.QueryMessage`` class is used for ordinary DNS query messages.

.. autoclass:: dns.message.QueryMessage
   :members:

The dns.message.ChainingResult Class
------------------------------------

Objects of the ``dns.message.ChainingResult`` class are returned by the
``dns.message.QueryMessage.resolve_chaining()`` method.

.. autoclass:: dns.message.ChainingResult
   :members:
