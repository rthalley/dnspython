.. _whatsnew:

What's New in dnspython 2.0.0
=============================

* Python 3.6 or newer is required.

* The license is now the ISC license.

* Rdata is now immutable.  Use ``dns.rdata.Rdata.replace()`` to make a new
  Rdata based on an existing one.

* dns.resolver.resolve() has been added, allowing control of whether search
  lists are used.  dns.resolver.query() is retained for
  backwards compatibility, but deprecated.  The default for search list
  behavior can be set at in the resolver object with the
  ``use_search_by_default`` parameter.  The default is False.

* DNS-over-TLS is supported with ``dns.query.tls()``.

* DNS-over-HTTPS is supported with ``dns.query.https()``, and the resolver
  will use DNS-over-HTTPS for a nameserver which is an HTTPS URL.

* Basic query and resolver support for the Trio, Curio, and asyncio
  asynchronous I/O libraries has been added in ``dns.asyncquery`` and
  ``dns.asyncresolver``.  This API should be viewed as experimental as
  asynchronous I/O support in dnspython is still evolving.

* TSIG now defaults to using SHA-256.

* Basic type info has been added to some functions.  Future releases will
  have comprehensive type info.

* from_text() functions now have a ``relativize_to`` parameter.

* python-cryptography is now used for DNSSEC.

* Ed25519 and Ed448 signatures are now supported.

* A helper for NSEC3 generating hashes has been added.

* SHA384 DS records are supported.

* Rdatasets and RRsets are much faster.

* dns.resolver.resolve_address() has been added, allowing easy address-to-name
  lookups.

* dns.reversename functions now allow an alternate origin to be specified.

* The ``repr`` form of Rdatasets and RRsets now includes the rdata.

* A number of standard resolv.conf options are now parsed.

* The nameserver and port used to get a response are now part of the resolver's
  ``Answer`` object.

* The NINFO record is supported.

* The ``dns.hash`` module has been removed; just use Python's native
  ``hashlib`` module.

* Rounding is done in the standard python 3 fashion; dnspython 1.x rounded
  in the python 2 style on both python 2 and 3.

* The resolver will now do negative caching if a cache has been configured.

* TSIG and OPT now have rdata types.

* The class for query messages is now QueryMessage.  Class Message is now a
  base class, and is also used for messages for which we don't have a better
  class.  Update messages are now class UpdateMessage, though class Update
  is retained for compatibility.

* Support for Windows 95, 98, and ME has been removed.
