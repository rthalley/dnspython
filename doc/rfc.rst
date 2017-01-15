.. _rfc:

DNS RFC Reference
=================

The DNS is defined by a large number of RFCs, many of which have been
extensively updated or obsoleted.  This chapter aims to provide a
roadmap and reference for this confusing space.  The chapter does not
aim to be encyclopedically complete, however, as the key information
would then be lost in the noise.  The curious are encouraged to click
on the "Updated by" links on the IETF pages to see the finer points, or
the "Obsoletes" links to go spelunking into the history of the DNS.

DNSSEC gets its own section instead of being included in the "Core"
list because there are many DNSSEC related RFCs and it's helpful to group
them together.  It's not a statement that DNSSEC isn't part of the "Core"
of the DNS.

The IANA `DNS Parameters <http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml>`_ registry is the offical reference site for all DNS
constants.


Core RFCs
---------

`RFC 1034 <https://tools.ietf.org/html/rfc1034>`_
    Introduction to the DNS and description of basic behavior.

`RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
    The core DNS wire protocol and master file format.

`RFC 1995 <https://tools.ietf.org/html/rfc1995>`_
    Incremental zone transfer (IXFR).

`RFC 1996 <https://tools.ietf.org/html/rfc1996>`_
    The NOTIFY protocol.

`RFC 2181 <https://tools.ietf.org/html/rfc2181>`_
    Clarifications to the specification.

`RFC 2308 <https://tools.ietf.org/html/rfc2308>`_
    Negative Caching.

`RFC 2845 <https://tools.ietf.org/html/rfc2845>`_
    Transaction Sigatures (TSIG)

`RFC 3007 <https://tools.ietf.org/html/rfc3007>`_
    Dynamic Updates

`RFC 3645 <https://tools.ietf.org/html/rfc3645>`_
    GSS-TSIG.

    Note that dnspython does not currently have GSS-TSIG support.
    GSS-TSIG is most frequently used when updating Microsoft
    Active-Directory-based DNS servers.
    
`RFC 5936 <https://tools.ietf.org/html/rfc5936>`_
    Zone transfers (AXFR).

`RFC 6891 <https://tools.ietf.org/html/rfc6891>`_
    EDNS (version 0)
    
`RFC 8020 <https://tools.ietf.org/html/rfc8020>`_
    Clarification on the meaning of NXDOMAIN.

DNSSEC RFCs
-----------

`RFC 4033 <https://tools.ietf.org/html/rfc4033>`_
    Introduction and requirements.

`RFC 4034 <https://tools.ietf.org/html/rfc4034>`_
    Resource records.

`RFC 4035 <https://tools.ietf.org/html/rfc4035>`_
    Protocol.

`RFC 4470 <https://tools.ietf.org/html/rfc4470>`_
    Minimally covering NSEC records and On-line Signing.
    
`RFC 6840 <https://tools.ietf.org/html/rfc6840>`_
    Clarifications and implementation Notes.

Misc RFCs
---------

`RFC 1101 <https://tools.ietf.org/html/rfc1101>`_
    Reverse mapping name form for IPv4.

`RFC 1982 <https://tools.ietf.org/html/rfc1982>`_
    Serial number arithmetic.

`RFC 4343 <https://tools.ietf.org/html/rfc4343>`_
    Case-sensitivity clarification.

RFCs for RR types
-----------------

There are many more RR types than are listed here; if a type is not
listed it means it is obsolete, deprecated, or rare "in the wild".
Some newer types that are currently rare are listed because they may
well be more heavily used in the not-to-distant future.
See the
IANA `DNS Parameters <http://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml>`_ registry for a complete list.

A
    `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
AAAA
    `RFC 3596 <https://tools.ietf.org/html/rfc3596>`_
CDS
    `RFC 7344 <https://tools.ietf.org/html/rfc7344>`_
CDNSKEY
    `RFC 7344 <https://tools.ietf.org/html/rfc7344>`_
CNAME
    `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
CSYNC
    `RFC 7477 <https://tools.ietf.org/html/rfc7477>`_
DNAME
    `RFC 6672 <https://tools.ietf.org/html/rfc6672>`_
DNSKEY
    `RFC 4034 <https://tools.ietf.org/html/rfc4034>`_
DS
    `RFC 4034 <https://tools.ietf.org/html/rfc4034>`_
LOC
    `RFC 1876 <https://tools.ietf.org/html/rfc1876>`_
MX
    `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
NAPTR
    `RFC 3403 <https://tools.ietf.org/html/rfc3403>`_
NS
    `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
NSEC
    `RFC 4034 <https://tools.ietf.org/html/rfc4034>`_
NSEC3
    `RFC 5155 <https://tools.ietf.org/html/rfc5155>`_
NSEC3PARAM
    `RFC 5155 <https://tools.ietf.org/html/rfc5155>`_
OPENPGPKEY
    `RFC 7929 <https://tools.ietf.org/html/rfc7929>`_
PTR
    `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
RRSIG
    `RFC 4034 <https://tools.ietf.org/html/rfc4034>`_
SOA
    `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
SPF
    `RFC 7208 <https://tools.ietf.org/html/rfc7208>`_
SRV
    `RFC 2782 <https://tools.ietf.org/html/rfc2782>`_
TLSA
    `RFC 6698 <https://tools.ietf.org/html/rfc6698>`_
TXT
    `RFC 1035 <https://tools.ietf.org/html/rfc1035>`_
