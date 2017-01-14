.. module:: dns.message
.. _message:

DNS Messages
============

Objects of the dns.message.Message class represent a single DNS message.

The module provides tools for constructing and manipulating messages.
TSIG signatures and EDNS are also supported.  Messages can be dumped to
a textual form, and also read from that form.

.. toctree::

   message-class
   message-make
