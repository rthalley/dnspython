.. _message-flags:

Message Flags
=============

DNS message flags are used for signalling of various kinds
in the DNS protocol.  For example, the ``QR`` flag indicates
that a message is a response to a prior query.

Messages flags are encoded in two locations: the DNS header
and the EDNS flags field.

Header Flags
------------

.. autodata:: dns.flags.QR
.. autodata:: dns.flags.AA
.. autodata:: dns.flags.TC
.. autodata:: dns.flags.RD
.. autodata:: dns.flags.RA
.. autodata:: dns.flags.AD
.. autodata:: dns.flags.CD

.. autofunction:: dns.flags.from_text
.. autofunction:: dns.flags.to_text
              
EDNS Flags
----------

.. autodata:: dns.flags.DO

.. autofunction:: dns.flags.edns_from_text
.. autofunction:: dns.flags.edns_to_text
