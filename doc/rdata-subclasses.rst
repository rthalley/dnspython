.. _rdata-subclasses:

Rdata Subclass Reference
========================

.. autoclass:: dns.rdata.GenericRdata

   .. attribute:: data

      A ``bytes`` containing the rdata's value.

.. autoclass:: dns.rdtypes.ANY.AFSDB.AFSDB
   :members:

   .. attribute:: subtype

   An ``int``, the AFSDB subtype

   .. attribute:: hostname

   A ``dns.name.Name``, the AFSDB hostname.

.. autoclass:: dns.rdtypes.ANY.AVC.AVC
   :members:

   .. attribute:: strings

   A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.CAA.CAA
   :members:

   .. attribute:: flags

   An ``int``, the flags

   .. attribute:: tag
                  
   A ``bytes``, the tag

   .. attribute:: value
                  
   A ``bytes``, the value

.. autoclass:: dns.rdtypes.ANY.CDNSKEY.CDNSKEY
   :members:

   .. attribute:: flags

       An ``int``, the key's flags.

   .. attribute:: protocol

      An ``int``, the protocol for which this key may be used.

   .. attribute:: algorithm:

      An ``int``, the algorithm used for the key.

   .. attribute:: key

      A ``bytes``, the public key.

.. autoclass:: dns.rdtypes.ANY.CDS.CDS
   :members:

   .. attribute::  key_tag

      An ``int``, the key tag.

   .. attribute:: algorithm
      
      An ``int``, the algorithm used for the key.

   .. attribute:: digest_type

      An ``int``, the digest type.

   .. attribute:: digest

      A ``bytes``, the digest of the key.

.. autoclass:: dns.rdtypes.ANY.CERT.CERT
   :members:

   .. attribute:: certificate_type

   An ``int``, the certificate type.

   .. attribute:: key_tag

   An ``int``, the key tag.

   .. attribute:: algorithm

   An ``int``, the algorithm.                  

   .. attribute:: certificate

   A ``bytes``, the certificate or CRL.

.. autoclass:: dns.rdtypes.ANY.CNAME.CNAME
   :members:

   .. attribute:: target

   A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.ANY.CSYNC.CSYNC
   :members:

    .. attribute:: serial

    An ``int``, the SOA serial number.

    .. attribute:: flags

    An ``int``, the CSYNC flags.

    .. attribute:: windows

    A tuple of ``(int, bytes)`` tuples.

.. autoclass:: dns.rdtypes.ANY.DLV.DLV
   :members:

   .. attribute::  key_tag

      An ``int``, the key tag.

   .. attribute:: algorithm
      
      An ``int``, the algorithm used for the key.

   .. attribute:: digest_type

      An ``int``, the digest type.

   .. attribute:: digest

      A ``bytes``, the digest of the key.

.. autoclass:: dns.rdtypes.ANY.DNAME.DNAME
   :members:

   .. attribute:: target

   A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.ANY.DNSKEY.DNSKEY
   :members:

   .. attribute:: flags

       An ``int``, the key's flags.

   .. attribute:: protocol

      An ``int``, the protocol for which this key may be used.

   .. attribute:: algorithm:

      An ``int``, the algorithm used for the key.

   .. attribute:: key

      A ``bytes``, the public key.

.. autoclass:: dns.rdtypes.ANY.DS.DS
   :members:

   .. attribute::  key_tag

      An ``int``, the key tag.

   .. attribute:: algorithm
      
      An ``int``, the algorithm used for the key.

   .. attribute:: digest_type

      An ``int``, the digest type.

   .. attribute:: digest

      A ``bytes``, the digest of the key.

.. autoclass:: dns.rdtypes.ANY.EUI48.EUI48
   :members:

   .. attribute:: eui

      A ``bytes``, 48-bit Extended Unique Identifier (EUI-48).

.. autoclass:: dns.rdtypes.ANY.EUI64.EUI64
   :members:

   .. attribute:: eui

      A ``bytes``, 64-bit Extended Unique Identifier (EUI-64).

.. autoclass:: dns.rdtypes.ANY.GPOS.GPOS
   :members:

   .. attribute:: latitude

   A ``bytes``, the latitude

   .. attribute:: longitude

   A ``bytes``, the longitude

   .. attribute:: altitude

   A ``bytes``, the altitude

.. autoclass:: dns.rdtypes.ANY.HINFO.HINFO
   :members:

   .. attribute:: cpu

   A ``bytes``, the CPU type.

   .. attribute:: os

   A ``bytes``, the OS type.

.. autoclass:: dns.rdtypes.ANY.HIP.HIP
   :members:

   .. attribute:: hit

   A ``bytes``, the host identity tag.

   .. attribute:: algorithm

   An ``int``, the public key cryptographic algorithm.

   .. attribute:: key

   A ``bytes``, the public key.

   .. attribute:: servers

   A tuple of ``dns.name.Name`` objects, the rendezvous servers.

.. autoclass:: dns.rdtypes.ANY.ISDN.ISDN
   :members:
      
   .. attribute:: address

   A ``bytes``, the ISDN address.

   .. attribute:: subaddress

   A ``bytes`` the ISDN subaddress (or ``b''`` if not present).

.. autoclass:: dns.rdtypes.ANY.LOC.LOC
   :members:

   .. attribute:: latitude

   An ``(int, int, int, int, int)`` tuple specifying the degrees, minutes,
   seconds, milliseconds, and sign of the latitude.

   .. attribute:: longitude

   An ``(int, int, int, int, int)`` tuple specifying the degrees, minutes,
   seconds, milliseconds, and sign of the longitude.

   .. attribute:: altitude

   A ``float``, the altitude, in centimeters.

   .. attribute:: size

   A ``float``, the size of the sphere, in centimeters.

   .. attribute:: horizontal_precision

   A ``float``, the horizontal precision, in centimeters.

   .. attribute:: vertical_precision

   A ``float``, the vertical precision, in centimeters.

.. autoclass:: dns.rdtypes.ANY.MX.MX
   :members:

   .. attribute:: preference

   An ``int``, the preference value

   .. attribute:: exchange

   A ``dns.name.Name``, the exchange name.

.. autoclass:: dns.rdtypes.ANY.NINFO.NINFO

   .. attribute:: strings

   A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.NS.NS
   :members:

   .. attribute:: target

   A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.ANY.NSEC
   :members:

.. autoclass:: dns.rdtypes.ANY.NSEC3
   :members:

.. autoclass:: dns.rdtypes.ANY.NSEC3PARAM
   :members:

.. autoclass:: dns.rdtypes.ANY.OPENPGPKEY
   :members:

.. autoclass:: dns.rdtypes.ANY.PTR.PTR
   :members:

   .. attribute:: target

   A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.ANY.RP
   :members:

.. autoclass:: dns.rdtypes.ANY.RRSIG
   :members:

.. autoclass:: dns.rdtypes.ANY.RT.RT
   :members:

   .. attribute:: preference

   An ``int``, the preference value

   .. attribute:: exchange

   A ``dns.name.Name``, the exchange name.
      
.. autoclass:: dns.rdtypes.ANY.SOA
   :members:

.. autoclass:: dns.rdtypes.ANY.SPF.SPF
   :members:

   .. attribute:: strings

   A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.SSHFP
   :members:

.. autoclass:: dns.rdtypes.ANY.TLSA
   :members:

.. autoclass:: dns.rdtypes.ANY.TXT.TXT
   :members:

   .. attribute:: strings

   A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.URI
   :members:

.. autoclass:: dns.rdtypes.ANY.X25
   :members:

.. autoclass:: dns.rdtypes.IN.A
   :members:

.. autoclass:: dns.rdtypes.IN.AAAA
   :members:

.. autoclass:: dns.rdtypes.IN.APL
   :members:

.. autoclass:: dns.rdtypes.IN.DHCID
   :members:

.. autoclass:: dns.rdtypes.IN.IPSECKEY
   :members:

.. autoclass:: dns.rdtypes.IN.KX
   :members:

.. autoclass:: dns.rdtypes.IN.NAPTR
   :members:

.. autoclass:: dns.rdtypes.IN.NSAP
   :members:

.. autoclass:: dns.rdtypes.IN.NSAP_PTR.NSAP_PTR
   :members:

   .. attribute:: target

   A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.IN.PX
   :members:

.. autoclass:: dns.rdtypes.IN.SRV
   :members:

.. autoclass:: dns.rdtypes.IN.WKS
   :members:

