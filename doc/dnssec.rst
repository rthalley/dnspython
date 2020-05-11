.. module:: dns.dnssec
.. _dnssec:

DNSSEC
======

Dnspython can do simple DNSSEC signature validation, but currently has no
facilities for signing.  In order to use DNSSEC functions, you must have
``python cryptography`` installed.

DNSSEC Functions
----------------

.. autofunction:: dns.dnssec.algorithm_from_text
.. autofunction:: dns.dnssec.algorithm_to_text
.. autofunction:: dns.dnssec.key_id
.. autofunction:: dns.dnssec.make_ds
.. autofunction:: dns.dnssec.validate
.. autofunction:: dns.dnssec.validate_rrsig
.. autofunction:: dns.dnssec.nsec3_hash

DNSSEC Algorithms
-----------------

.. autodata:: dns.dnssec.RSAMD5
.. autodata:: dns.dnssec.DH
.. autodata:: dns.dnssec.DSA
.. autodata:: dns.dnssec.ECC
.. autodata:: dns.dnssec.RSASHA1
.. autodata:: dns.dnssec.DSANSEC3SHA1
.. autodata:: dns.dnssec.RSASHA1NSEC3SHA1
.. autodata:: dns.dnssec.RSASHA256
.. autodata:: dns.dnssec.RSASHA512
.. autodata:: dns.dnssec.ECDSAP256SHA256
.. autodata:: dns.dnssec.ECDSAP384SHA384
.. autodata:: dns.dnssec.INDIRECT
.. autodata:: dns.dnssec.PRIVATEDNS
.. autodata:: dns.dnssec.PRIVATEOID
