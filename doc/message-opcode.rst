.. _message-opcode:

Message Opcodes
---------------

DNS Opcodes describe what kind of operation a DNS message is requesting
or replying to.  Opcodes are embedded in the flags field in the DNS
header.

.. autodata:: dns.opcode.QUERY
.. autodata:: dns.opcode.IQUERY
.. autodata:: dns.opcode.STATUS
.. autodata:: dns.opcode.NOTIFY
.. autodata:: dns.opcode.UPDATE

.. autofunction:: dns.opcode.from_text
.. autofunction:: dns.opcode.to_text
.. autofunction:: dns.opcode.from_flags
.. autofunction:: dns.opcode.to_flags
.. autofunction:: dns.opcode.is_update
