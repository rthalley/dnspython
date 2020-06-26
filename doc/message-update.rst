.. _message-update:

The dns.update.UpdateMessage Class
----------------------------------

The ``dns.update.UpdateMessage`` class is used for DNS Dynamic Update
messages.  It provides section access using the DNS Dynamic Update
section names, and a variety of convenience methods for constructing
dynamic updates.

.. autoclass:: dns.update.UpdateMessage
   :members:

The following constants may be used to specify sections in the
``find_rrset()`` and ``get_rrset()`` methods:

.. autodata:: dns.update.ZONE
.. autodata:: dns.update.PREREQ
.. autodata:: dns.update.UPDATE
.. autodata:: dns.update.ADDITIONAL
