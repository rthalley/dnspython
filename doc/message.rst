.. module:: dns.message
.. _message:

DNS Messages
============

Objects of the dns.message.Message class and its subclasses represent
a single DNS message, as defined by `RFC 1035
<https://tools.ietf.org/html/rfc1035>`_ and its many updates and
extensions.

The module provides tools for constructing and manipulating messages.
TSIG signatures and EDNS are also supported.  Messages can be dumped to
a textual form, and also read from that form.

Dnspython has also GSS-TSIG support, but the current API is low-level.  See `this
discussion <https://github.com/rthalley/dnspython/pull/530#issuecomment-658959755>`_
for the details.

.. toctree::

   message-class
   message-make
   message-flags
   message-opcode
   message-rcode
   message-edns
   message-query
   message-update
