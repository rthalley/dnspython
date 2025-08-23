.. _rdata-subclasses:

Rdata Subclass Reference
========================

.. _rdata-subclasses-any:

Universal Types
---------------

.. autoclass:: dns.rdata.GenericRdata

   .. attribute:: data

      A ``bytes`` containing the rdata's value.

.. autoclass:: dns.rdtypes.ANY.AFSDB.AFSDB
   :members:

.. autoclass:: dns.rdtypes.ANY.AMTRELAY.AMTRELAY
   :members:

   .. attribute:: precedence

   An ``int``, the 8-bit unsigned integer preference.

   .. attribute:: discovery_optional

   A ``bool``, specifying whether discovery is optional or not.

   .. attribute:: relay_type

   An ``int``, the 8-bit unsigned integer relay type.

   .. attribute:: relay

   A ``dns.rdtypes.ANY.AMTRELAY.Relay`` instance, the relay.

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

.. autoclass:: dns.rdtypes.ANY.DSYNC.DSYNC
   :members:

   .. attribute:: rrtype

      A ``dns.rdatatype.RdataType``, the type this DSYNC record will notify about.

   .. attribute:: scheme

      A ``dns.rdtypes.ANY.DSYNC.Scheme`` the scheme to use, typically
      ``dns.rdtypes.ANY.DSYNC.Scheme.NOTIFY``.

   .. attribute:: port

      An ``int``, the port to notify.

   .. attribute:: target

      A ``dns.name.Name``, the hostname of the notification receiver.

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

.. autoclass:: dns.rdtypes.ANY.L32.L32
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: locator32

      A ``string``, the 32-bit locator value in the form of an IPv4 address.

.. autoclass:: dns.rdtypes.ANY.L64.L64
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: locator64

      A ``string``, the 64-bit locator value in colon-separated-hex form.

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

.. autoclass:: dns.rdtypes.ANY.LP.LP
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: fqdn

      A ``dns.name.Name``, the domain name of a locator.

.. autoclass:: dns.rdtypes.ANY.MX.MX
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: exchange

      A ``dns.name.Name``, the exchange name.

.. autoclass:: dns.rdtypes.ANY.NID.NID
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: nodeid

      A ``string``, the 64-bit nodeid value in colon-separated-hex form.

.. autoclass:: dns.rdtypes.ANY.NINFO.NINFO

   .. attribute:: strings

      A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.NS.NS
   :members:

   .. attribute:: target

      A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.ANY.NSEC.NSEC
   :members:

   .. attribute:: next

      A ``dns.name.Name``, the next name

   .. attribute:: windows

      A tuple of ``(int, bytes)`` tuples.

.. autoclass:: dns.rdtypes.ANY.NSEC3.NSEC3
   :members:

   .. attribute:: algorithm:

      An ``int``, the algorithm used for the hash.

   .. attribute:: flags:

      An ``int``, the flags.

   .. attribute:: iterations:

      An ``int``, the number of iterations.

   .. attribute:: salt

      A ``bytes``, the salt.

   .. attribute:: next

      A ``bytes``, the next name hash.

   .. attribute:: windows

      A tuple of ``(int, bytes)`` tuples.

.. autoclass:: dns.rdtypes.ANY.NSEC3PARAM.NSEC3PARAM
   :members:

   .. attribute:: algorithm:

      An ``int``, the algorithm used for the hash.

   .. attribute:: flags:

      An ``int``, the flags.

   .. attribute:: iterations:

      An ``int``, the number of iterations.

   .. attribute:: salt

      A ``bytes``, the salt.

.. autoclass:: dns.rdtypes.ANY.OPENPGPKEY.OPENPGPKEY
   :members:

   .. attribute:: key

      A ``bytes``, the key.

.. autoclass:: dns.rdtypes.ANY.PTR.PTR
   :members:

   .. attribute:: target

      A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.ANY.RESINFO.RESINFO
   :members:

   .. attribute:: strings

      A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.RP.RP
   :members:

   .. attribute:: mbox

      A ``dns.name.Name``, the responsible person's mailbox.

   .. attribute:: txt

      A ``dns.name.Name``, the owner name of a node with TXT records,
      or the root name if no TXT records are associated with this RP.

.. autoclass:: dns.rdtypes.ANY.RRSIG.RRSIG
   :members:

   .. attribute:: type_covered

      An ``int``, the rdata type this signature covers.

   .. attribute:: algorithm

      An ``int``, the algorithm used for the signature.

   .. attribute:: labels

      An ``int``, the number of labels.

   .. attribute:: original_ttl

      An ``int``, the original TTL.

   .. attribute:: expiration

      An `int`, the signature expiration time.

   .. attribute:: inception

      An `int`, the signature inception time.

   .. attribute:: key_tag

      An `int`, the key tag.

   .. attribute:: signer

      A ``dns.name.Name``, the signer.

   .. attribute:: signature

      A ``bytes``, the signature.

.. autoclass:: dns.rdtypes.ANY.RT.RT
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: exchange

      A ``dns.name.Name``, the exchange name.

.. autoclass:: dns.rdtypes.ANY.SMIMEA.SMIMEA
   :members:

   .. attribute:: usage

      An ``int``, the certificate usage.

   .. attribute:: selector

      An ``int``, the selector.

   .. attribute:: mtype

      An ``int``, the matching type.

   .. attribute:: cert

      A ``bytes``, the certificate association data.

.. autoclass:: dns.rdtypes.ANY.SOA.SOA
   :members:

   .. attribute:: mname

      A ``dns.name.Name``, the MNAME (master name).

   .. attribute:: rname

      A ``dns.name.Name``, the RNAME (responsible name).

   .. attribute:: serial

      An ``int``, the zone's serial number.

   .. attribute:: refresh

      An ``int``, the zone's refresh value (in seconds).

   .. attribute:: retry

      An ``int``, the zone's retry value (in seconds).

   .. attribute:: expire

      An ``int``, the zone's expiration value (in seconds).

   .. attribute:: minimum

      An ``int``, the zone's negative caching time (in seconds, called
      "minimum" for historical reasons).

.. autoclass:: dns.rdtypes.ANY.SPF.SPF
   :members:

   .. attribute:: strings

      A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.SSHFP.SSHFP
   :members:

   .. attribute:: algorithm

      An ``int``, the algorithm.

   .. attribute:: fp_type

      An ``int``, the digest type.

   .. attribute:: fingerprint

      A ``bytes``, the fingerprint.

.. autoclass:: dns.rdtypes.ANY.TLSA.TLSA
   :members:

   .. attribute:: usage

      An ``int``, the certificate usage.

   .. attribute:: selector

      An ``int``, the selector.

   .. attribute:: mtype

      An ``int``, the matching type.

   .. attribute:: cert

      A ``bytes``, the certificate association data.

.. autoclass:: dns.rdtypes.ANY.TXT.TXT
   :members:

   .. attribute:: strings

      A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.URI.URI
   :members:

   .. attribute:: priority

      An ``int``, the priority.

   .. attribute:: weight

      An ``int``, the weight.

   .. attribute:: target

      A ``dns.name.Name``, the target.

.. autoclass:: dns.rdtypes.ANY.WALLET.WALLET
   :members:

   .. attribute:: strings

      A tuple of ``bytes``, the list of strings.

.. autoclass:: dns.rdtypes.ANY.X25.X25
   :members:

   .. attribute:: address

      A ``bytes``, the PSDN address.

.. _rdata-subclasses-in:

Types specific to class IN
--------------------------

.. autoclass:: dns.rdtypes.IN.A.A
   :members:

   .. attribute:: address

      A ``str``, an IPv4 address in the standard "dotted quad" text format.

.. autoclass:: dns.rdtypes.IN.AAAA.AAAA
   :members:

   .. attribute:: address

      A ``str``, an IPv6 address in the standard text format.

.. autoclass:: dns.rdtypes.IN.APL.APLItem
   :members:

   .. attribute:: family

      An ``int``, the address family (in the IANA address family registry).

   .. attribute:: negation

      A ``bool``, is this item negated?

   .. attribute:: address

      A ``str``, the address.

   .. attribute:: prefix

      An ``int``, the prefix length.

.. autoclass:: dns.rdtypes.IN.APL.APL
   :members:

   .. attribute:: items

      A tuple of ``dns.rdtypes.IN.APL.APLItem``.

.. autoclass:: dns.rdtypes.IN.DHCID.DHCID
   :members:

   .. attribute:: data

      A ``bytes``, the data (the content of the RR is opaque as far as
      the DNS is concerned).

.. autoclass:: dns.rdtypes.IN.HTTPS.HTTPS
   :members:

   .. attribute:: priority

      An ``int``, the unsigned 16-bit integer priority.

   .. attribute:: target

      A ``dns.name.Name``, the target name.

   .. attribute:: params

      A ``dict[dns.rdtypes.svcbbase.ParamKey, dns.rdtypes.svcbbase.Param]``, the
      parameters.  See the dedicated section :ref:`svcb-https-params` below for
      more information on the parameter types.

.. autoclass:: dns.rdtypes.IN.IPSECKEY.IPSECKEY
   :members:

   .. attribute:: precedence

      An ``int``, the precedence for the key data.

   .. attribute:: prefix

      An ``int``, the prefix length.

   .. attribute:: gateway_type

      An ``int``, the gateway type.

   .. attribute:: algorithm

      An ``int``, the algorithm to use.

   .. attribute:: gateway

      The gateway.  This value may be ``None``, a ``str` with an IPv4 or
      IPV6 address, or a ``dns.name.Name``.

   .. attribute:: key

      A ``bytes``, the public key.

.. autoclass:: dns.rdtypes.IN.KX.KX
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: exchange

      A ``dns.name.Name``, the exchange name.

.. autoclass:: dns.rdtypes.IN.NAPTR.NAPTR
   :members:

   .. attribute:: order

      An ``int``, the order.

   .. attribute:: preference

      An ``int``, the preference.

   .. attribute:: flags

      A ``bytes``, the flags.

   .. attribute:: service

      A ``bytes``, the service.

   .. attribute:: regexp

      A ``bytes``, the regular expression.

   .. attribute:: replacement

      A ``dns.name.Name``, the replacement name.

.. autoclass:: dns.rdtypes.IN.NSAP.NSAP
   :members:

   .. attribute:: address

      A ``bytes``, a NSAP address.

.. autoclass:: dns.rdtypes.IN.NSAP_PTR.NSAP_PTR
   :members:

   .. attribute:: target

      A ``dns.name.Name``, the target name.

.. autoclass:: dns.rdtypes.IN.PX.PX
   :members:

   .. attribute:: preference

      An ``int``, the preference value.

   .. attribute:: map822

      A ``dns.name.Name``, the map822 name.

   .. attribute:: mapx400

      A ``dns.name.Name``, the mapx400 name.

.. autoclass:: dns.rdtypes.IN.SRV.SRV
   :members:

   .. attribute:: priority

      An ``int``, the priority.

   .. attribute:: weight

      An ``int``, the weight.

   .. attribute:: port

      An ``int``, the port.

   .. attribute:: target

      A ``dns.name.Name``, the target host.

.. autoclass:: dns.rdtypes.IN.SVCB.SVCB
   :members:

   .. attribute:: priority

      An ``int``, the unsigned 16-bit integer priority.

   .. attribute:: target

      A ``dns.name.Name``, the target name.

   .. attribute:: params

      A ``dict[dns.rdtypes.svcbbase.ParamKey, dns.rdtypes.svcbbase.Param]``, the
      parameters.  See the dedicated section :ref:`svcb-https-params` below for
      more information on the parameter types.

.. autoclass:: dns.rdtypes.IN.WKS.WKS
   :members:

   .. attribute:: address

      A ``str``, the address.

   .. attribute:: protocol

      An ``int``, the protocol.

   .. attribute:: bitmap

      A ``bytes``, the bitmap.

.. _svcb-https-params:

SVCB and HTTPS Parameter Classes
--------------------------------

.. autoclass:: dns.rdtypes.svcbbase.ParamKey
   :members:

   .. attribute:: ALPN
   .. attribute:: ECH
   .. attribute:: IPV4HINT
   .. attribute:: IPV6HINT
   .. attribute:: MANDATORY
   .. attribute:: NO_DEFAULT_ALPN
   .. attribute:: PORT

.. autoclass:: dns.rdtypes.svcbbase.Param
   :members:

.. autoclass:: dns.rdtypes.svcbbase.GenericParam
   :members:

   .. attribute:: value

      A ``bytes``, the value of the parameter.

.. autoclass:: dns.rdtypes.svcbbase.MandatoryParam
   :members:

   .. attribute:: keys

      A tuple of ``ParamKey``, the keys which are mandatory.

.. autoclass:: dns.rdtypes.svcbbase.ALPNParam
   :members:

   .. attribute:: ids

      A tuple of ``bytes`` values, the APLN ids.

.. autoclass:: dns.rdtypes.svcbbase.PortParam
   :members:

   .. attribute:: port

      An ``int``, the unsigned 16-bit integer port.

.. autoclass:: dns.rdtypes.svcbbase.IPv4HintParam
   :members:

   .. attribute:: addresses

      A tuple of ``string``, which each string is an IPv4 address.

.. autoclass:: dns.rdtypes.svcbbase.IPv6HintParam
   :members:

   .. attribute:: addresses

      A tuple of ``string``, which each string is an IPv6 address.

.. autoclass:: dns.rdtypes.svcbbase.ECHParam
   :members:

   .. attribute:: ech

      A ``bytes``.
