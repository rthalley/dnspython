.. _message-rcode:

Message Rcodes
--------------

A DNS Rcode describes the result of a DNS request.  If EDNS is not in
use, then the rcode is encoded solely in the DNS header.   If EDNS is
in use, then the rcode is encoded using bits form both the header and
the EDNS OPT RR.

.. autodata:: dns.rcode.NOERROR
.. autodata:: dns.rcode.FORMERR
.. autodata:: dns.rcode.SERVFAIL
.. autodata:: dns.rcode.NXDOMAIN
.. autodata:: dns.rcode.NOTIMP
.. autodata:: dns.rcode.REFUSED
.. autodata:: dns.rcode.YXDOMAIN
.. autodata:: dns.rcode.YXRRSET
.. autodata:: dns.rcode.NXRRSET
.. autodata:: dns.rcode.NOTAUTH
.. autodata:: dns.rcode.NOTZONE
.. autodata:: dns.rcode.BADVERS

.. autofunction:: dns.rcode.from_text
.. autofunction:: dns.rcode.to_text
.. autofunction:: dns.rcode.from_flags
.. autofunction:: dns.rcode.to_flags
