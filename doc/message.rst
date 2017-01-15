.. module:: dns.message
.. _message:

DNS Messages
============

Objects of the dns.message.Message class represent a single DNS message,
as defined by `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_ and its
many updates and extensions.

The module provides tools for constructing and manipulating messages.
TSIG signatures and EDNS are also supported.  Messages can be dumped to
a textual form, and also read from that form.

.. toctree::

   message-class
   message-make
   message-flags
   message-opcode
   message-rcode
   message-edns
   message-update
