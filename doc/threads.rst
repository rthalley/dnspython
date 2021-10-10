.. _threads:

Using Dnspython with Threads
----------------------------

The dnspython ``Name`` and ``Rdata`` types are immutable, and thus thread-safe.

Container objects like ``Message``, ``Node``, ``Rdataset``, ``RRset``,
and ``Zone`` are not thread-safe, as they are mutable and not locked.
It is up to the caller to ensure safety if they are shared between
threads.

The ``VersionedZone``, however, is thread-safe.  VersionedZones offer 
read-only and read-write transactions.  Read-only transactions access an
immutable version, and all the objects returned, including containers, are
immutable.  Read-write transactions are only visible to their creator until
they are committed.  Transaction creation and commit are thread-safe.
Transaction objects should not be shared between threads.

The ``Resolver`` is not thread-safe with regards to configuration, but it is
safe for many threads to call the ``resolve()`` method of a resolver.
The cache implementations for the resolver are also thread-safe, so if a
web-crawling application associates an ``LRUCache`` with a Resolver, it will
be safe to have many crawler threads doing resolutions.

The ``dns.query`` methods are also thread-safe.  One caveat with these
functions is that if a socket or other context (e.g. a Requests
session or an SSL context) is passed to the function instead of
allowing the function to create it, then it is up to the application to
ensure thread safety if the context could be used by multiple threads.
