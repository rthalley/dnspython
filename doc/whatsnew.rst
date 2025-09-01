.. _whatsnew:

What's New in dnspython
=======================

2.8.0
-----

* dns/btreezone.py provides another zone versioned implementation built on top of a
  B-tree.  It maintains DNSSEC sort order, labels nodes as delegation points or glue,
  and can find the "bounds" of a name (useful for DNSSEC responses).

* dns/query.py now provides make_socket(), make_ssl_socket(), and make_ssl_context()
  to make using persistent connections with the query code easier.

* dns/win32util.py now supports explicitly setting the configuration method used to get
  system dns info, using the set_config_method() function.   There is a new configuration
  method that uses the Win32 API, which can be set using
  set_config_method(ConfigMethod.Win32).  We are considering making the Win32 API
  the default in the future as we believe it to be the most accurate.  Any feedback on
  it compared to the other methods is welcome.

* The DSYNC record is now supported.  This type is still in draft stage at the IETF
  and is subject to change.

* The minimum supported Python version is now 3.10.

2.7.0
-----

* dns.query.https() and dns.asyncquery.https() now support HTTP/3 and the http_version
  parameter may be used to specify which version to use.

* If the cryptography module is installed, then dnspython will now create deterministic
  ECDSA signatures by default.  Cryptography, if installed, must be at least version 43.
  Thanks to Jakob Schlyter for adding the feature.

* The RESINFO and WALLET RdataTypes are now supported.

* The COOKIE and Report-Channel EDNS0 options are now supported.

* All supported RdataTypes can now be imported at a single time rather than lazily on
  first use by calling dns.rdata.load_all_types().

* The SVCB and HTTPS records now support the ohttp parameter.

* xfr() and inbound_xfr() now share a common implementation.

* Tokens are now supported for QUIC and HTTP/3.

* dns.message.from_wire() now saves the input wire format in the Message's "wire"
  attribute.  Likewise, dns.message.Message.to_wire() now records the generated
  wire format in that attribute.

* The dns.message.Message object now has a get_options() helper to retrieve EDNS0
  options of a specified type, and an extended_errors() helper to retrieve the list
  of EDE options in a message (if any).

* dns.message.make_response() now has a copy mode which controls how sections are
  copied.  By default, a copy mode appropriate for the opcode is used.  This is
  currently dns.message.CopyMode.QUESTION for all opcodes.

* If an IP address is used as the hostname in a URL, the https query code now passes
  the sni_hostname to httpx as this is required to get httpx to validate the certificate
  and check for an IP subject alternative name.

* The minimum supported aioquic version is now 1.0.0.

* The minimum supported Python version is now 3.9.

2.6.1
-----

* The Tudoor fix ate legitimate Truncated exceptions, preventing the resolver from
  failing over to TCP and causing the query to timeout [#1053].

2.6.0
-----

* As mentioned in the "TuDoor" paper and the associated CVE-2023-29483, the dnspython
  stub resolver is vulnerable to a potential DoS if a bad-in-some-way response from the
  right address and port forged by an attacker arrives before a legitimate one on the
  UDP port dnspython is using for that query.

  This release addresses the issue by adopting the recommended mitigation, which is
  ignoring the bad packets and continuing to listen for a legitimate response until
  the timeout for the query has expired.

* Added support for the NSID EDNS option.

* Dnspython now looks for version metadata for optional packages and will not
  use them if they are too old.  This prevents possible exceptions when a
  feature like DoH is not desired in dnspython, but an old httpx is installed
  along with dnspython for some other purpose.

* The DoHNameserver class now allows GET to be used instead of the default POST,
  and also passes source and source_port correctly to the underlying query
  methods.

2.5.0
-----

* Dnspython now uses hatchling for builds.

* Asynchronous destinationless sockets now work on Windows.

* Cython is no longer supported due to various typing issues.

* Dnspython now explicitly canonicalizes IPv4 and IPv6 addresses.
  Previously it was possible for non-canonical IPv6 forms to be stored
  in a AAAA address, which would work correctly but possibly cause
  problmes if the address were used as a key in a dictionary.

* The number of messages in a section can be retrieved with
  section_count().

* Truncation preferences for messages can be specified.

* The length of a message can be automatically prepended when
  rendering.

* dns.message.create_response() automatically adds padding when
  required by RFC 8467.

* The TLS verify parameter is now supported by dns.query.tls(),
  and the DoH and DoT Nameserver subclasses.

* The MutableMapping used to store content in a zone may now be
  specified by a factory when subclassing.  Factories may also be
  provided for writable verisons and immutable versions.

* dns.name.Name now has predecessor() and successor() methods
  implementing RFC 4471.

* QUIC has had a number of bug fixes and also now supports session
  tickets for faster session resumption.

* The NSEC3 class now has a next_name() method for retrieving the next
  name as a dns.name.Name.

* Windows WMI interface detection should be more robust.

2.4.2
-----

* Async queries could wait forever instead of respecting the timeout if the timeout was
  0 and a packet was lost.  The timeout is now respected.

* Restore HTTP/2 support which was accidentally broken during the https refactoring done
  as part of 2.4.0.

* When an inception time and lifetime are specified, the signer now sets the expiration
  to the inception time plus lifetime, instead of the current time plus the lifetime.

2.4.1
-----

* Importing dns.dnssecalgs without the cryptography module installed no longer causes
  an ImportError.

* A number of timeout bugs with the asyncio backend have been fixed.

* DNS-over-QUIC for the asyncio backend now works for IPv6.

* Dnspython now enforces that the candidate DNSKEYs for DNSSEC signatures
  have protocol 3 and have the ZONE flag set.  This is a standards compliance issue more
  than a security issue as the legitimate authority would have to have published
  the non-compliant keys as well as updated their DS record in order for the records
  to validate (the DS digest includes both flags and protocol).  Dnspython will not
  make invalid keys by default, but does allow them to be created and used
  for testing purposes.

* Dependency specifications for optional features in the package metadata have been
  improved.

2.4.0
-----

* Python 3.8 or newer is required.

* The stub resolver now uses instances of ``dns.nameserver.Nameserver`` to represent
  remote recursive resolvers, and can communicate using
  DNS over UDP/TCP, HTTPS, TLS, and QUIC.  In additional to being able to specify
  an IPv4, IPv6, or HTTPS URL as a nameserver, instances of ``dns.nameserver.Nameserver``
  are now permitted.

* The DNS-over-HTTPS bootstrap address no longer causes URL rewriting.

* DNS-over-HTTPS now only uses httpx; support for requests has been dropped.  A source
  port may now be supplied when using httpx.

* DNSSEC zone signing with NSEC records is now supported. Thank you
  very much (again!) Jakob Schlyter!

* The resolver and async resolver now have the ``try_ddr()`` method, which will try to
  use Discovery of Designated Resolvers (DDR) to upgrade the connection from the stub
  resolver to the recursive server so that it uses DNS-over-HTTPS, DNS-over-TLS, or
  DNS-over-QUIC. This feature is currently experimental as the standard is still in
  draft stage.

* The resolver and async resolver now have the ``make_resolver_at()`` and
  ``resolve_at()`` functions, as a convenience for making queries to specific
  recursive servers.

* Curio support has been removed.

2.3.0
-----

* Python 3.7 or newer is required.

* Type annotations are now integrated with the source code and cover
  far more of the library.

* The get_soa() method has been added to dns.zone.Zone.

* The minimum TLS version is now 1.2.

* EDNS padding is now supported.  Messages with EDNS enabled and with a
  non-zero pad option will be automatically padded appropriately when
  converted to wire format.

* ``dns.zone.from_text()`` and ``dns.zone.from_file()`` now have an
  ``allow_directives`` parameter to allow finer control over how directives
  in zonefiles are processed.

* A preliminary implementation of DNS-over-QUIC has been added, and will be
  available if the aioquic library is present.  See ``dns.query.quic()``,
  ``dns.asyncquery.quic()``, and examples/doq.py for more info.  This API
  is subject to change in future releases.  For asynchronous I/O, both
  asyncio and Trio are supported, but Curio is not.

* DNSSEC signing support has been added to the ``dns.dnssec`` module, along with
  a number of functions to help generate DS, CDS, and CDNSKEY RRsets.  Thank you
  very much Jakob Schlyter!

* Curio asynchronous I/O support is deprecated as of this release and will
  be removed in a future release.

* The resolver object's ``nameserver`` field is planned to become a property in
  dnspython 2.4.  Writing to this field other than by direct assignment is deprecated,
  and so is depending on the mutability and form of the iterable returned when it is
  read.

2.2.1
-----

This release has no new features, but fixes the following issues:

* dns.zone.from_text failed if relativize was False and an origin was
  specified in the parameters.

* A number of types permitted an empty "rest of the rdata".

* L32, L64, LP, and NID were missing from dns/rdtypes/ANY/__init__.py

* The type definition for dns.resolver.resolve_address() was incorrect.

* dns/win32util.py erroneously had the executable bit set.

* The type definition for a number of asynchronous query routines was
  missing the default of None for the backend parameter.

* dns/tsigkeyring.py didn't import dns.tsig.

* A number of rdata types that have a "rest of the line" behavior for
  the last field of the rdata erroneously permitted an empty string.

* Timeout intervals are no longer reported with absurd precision in
  exception text.

2.2.0
-----

* SVCB and HTTPS records have been updated to track the evolving draft
  standard.

* The ZONEMD type has been added.

* The resolver now returns a LifetimeTimeout exception which includes
  an error trace like the NoNameservers exception.  This class is a subclass of
  dns.exception.Timeout for backwards compatibility.

* DNS-over-HTTPS will try to use HTTP/2 if the httpx and h2 packages
  are installed.

* DNS-over-HTTPS is now supported for asynchronous queries and resolutions.

* ``dns.zonefile.read_rrsets()`` has been added, which allows rrsets in zonefile
  format, or a restrition of it, to be read.  This function is useful for
  applications that want to read DNS data in text format, but do not want to
  use a Zone.

* On Windows systems, if the WMI module is available, the resolver will retrieve
  the nameserver from WMI instead of trying to figure it out by reading the
  registry.  This may lead to more accurate results in some cases.

* The CERT rdatatype now supports certificate types IPKIX, ISPKI, IPGP,
  ACPKIX, and IACPKIX.

* The CDS rdatatype now allows digest type 0.

* Dnspython zones now enforces that a node is either a CNAME node or
  an "other data" node.  A CNAME node contains only CNAME,
  RRSIG(CNAME), NSEC, RRSIG(NSEC), NSEC3, or RRSIG(NSEC3) rdatasets.
  An "other data" node contains any rdataset other than a CNAME or
  RRSIG(CNAME) rdataset.  The enforcement is "last update wins".  For
  example, if you have a node which contains a CNAME rdataset, and
  then add an MX rdataset to it, then the CNAME rdataset will be deleted.
  Likewise if you have a node containing an MX rdataset and add a
  CNAME rdataset, the MX rdataset will be deleted.

* Extended DNS Errors, as specified in RFC 8914, are now supported.

2.1.0
----------------------

* End-of-line comments are now associated with rdata when read from text.
  For backwards compatibility with prior versions of dnspython, they are
  only emitted in to_text() when requested.

* Synchronous I/O is a bit more efficient, as we now try the I/O and only
  use poll() or select() if the I/O would block.

* The resolver cache classes now offer basic hit and miss statistics, and
  the LRUCache can also provide hits for every cache key.

* The resolver has a canonical_name() method.

* There is now a registration mechanism for EDNS option types.

* The default EDNS payload size has changed from 1280 to 1232.

* The SVCB, HTTPS, and SMIMEA RR types are now supported.

* TSIG has been enhanced with TKEY and GSS-TSIG support.  Thanks to
  Nick Hall for writing this.

* Zones now can be updated via transactions.

* A new zone subclass, dns.versioned.Zone is available which has a
  thread-safe transaction implementation and support for keeping many
  versions of a zone.

* The zone file reading code has been adapted to use transactions, and
  is now a public API.

* Inbound zone transfer support has been rewritten and is available as
  dns.query.inbound_xfr() and dns.asyncquery.inbound_xfr().  It uses
  the transaction mechanism, and fully supports IXFR and AXFR.

2.0.0
-----

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
