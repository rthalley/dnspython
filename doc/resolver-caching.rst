.. _resolver-caching:

Resolver Caching Classes
========================

The dnspython resolver does not cache by default, but caching can be
enabled by creating a cache and assigning it to the resolver's *cache*
attribute.  If a cache has been configured, the resolver caches both
positive and negative responses.  The cache respects the DNS TTL of
the data, and will not return expired entries.

Two thread-safe cache implementations are provided, a simple
dictionary-based Cache, and an LRUCache which provides cache size
control suitable for use in web crawlers.  Both are subclasses of
a common base class which provides basic statistics.  The LRUCache can
also provide a hits count per cache entry.

.. autoclass:: dns.resolver.CacheBase
   :members:

.. autoclass:: dns.resolver.Cache
   :members:

.. autoclass:: dns.resolver.LRUCache
   :members:

.. autoclass:: dns.resolver.CacheStatistics
   :members:
