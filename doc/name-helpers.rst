.. _name-helpers:

Name Helpers
------------

Sometimes you want to look up an address in the DNS instead of a name.
Dnspython provides a helper functions for converting between addresses
and their "reverse map" form in the DNS.

For example:

========= =========================================================================
Address   DNS Reverse Name
========= =========================================================================
127.0.0.1 1.0.0.127.in-addr.arpa.
::1       1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.
========= =========================================================================

|

.. autofunction:: dns.reversename.from_address
.. autofunction:: dns.reversename.to_address

Dnspython also provides helpers for converting E.164 numbers (i.e.
telephone numbers) into the names used for them in the DNS.

For example:

================ ==================================
Number           DNS E.164 Name
================ ==================================
+1.650.555.1212  2.1.2.1.5.5.5.0.5.6.1.e164.arpa.
+44 20 7946 0123 3.2.1.0.6.4.9.7.0.2.4.4.e164.arpa.
================ ==================================

|

.. autofunction:: dns.e164.from_e164
.. autofunction:: dns.e164.to_e164

                  
