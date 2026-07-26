.. _zone-make:

Making DNS Zones
----------------

.. autofunction:: dns.zone.from_text
.. autofunction:: dns.zone.from_file
.. autofunction:: dns.zone.from_xfr

.. warning::

   These functions build a zone by applying every record they read as a change
   in a transaction, and by default there is no limit on the number of changes.
   When the input is untrusted -- for example a user-supplied master file or a
   "zone import" feature -- a small input can request a very large amount of
   work: a ``$GENERATE`` directive with a large range, or a deliberately huge
   zone, can consume excessive memory and CPU.

   When parsing untrusted input, pass a ``dns.transaction.TransactionLimiter``
   as ``transaction_setup`` to cap the number of changes.  It raises
   ``dns.transaction.TooManyChanges`` once the limit is exceeded::

       import dns.zone
       import dns.transaction

       limiter = dns.transaction.TransactionLimiter(100000)
       try:
           z = dns.zone.from_file("untrusted.zone", "example.", transaction_setup=limiter)
       except dns.transaction.TooManyChanges:
           ...  # reject the oversized input

   Choose a limit appropriate to your application; the same mechanism bounds
   oversized inbound zone transfers.  The default behaviour remains unlimited
   for backwards compatibility.
