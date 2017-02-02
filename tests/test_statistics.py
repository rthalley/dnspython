#!/usr/bin/env python

# A higher-level way
import dns.resolver
import dns.name

urls_cache = ['www.amazon.com', 'www.google.com', 'www.cern.ch', 'www.netflix.com', 'www.facebook.com', 'www.google.com', 'www.google.com']
urls_lru = ['www.amazon.com', 'www.google.com', 'www.cern.ch','www.amazon.com', 'www.netflix.com', 'www.facebook.com']
urls_rev = ['172.217.6.142', '172.217.6.132', '157.240.0.35', '52.0.47.132', '188.184.9.234']
resolver = dns.resolver.Resolver()
resolver.cache = dns.resolver.LRUCache(4)


def current_status():
    print("-------------------CACHE STATUS-------------------")
    print("  Usage rate:        " + str(resolver.cache.get_usage_rate()))
    print("  Positive hits:     " + str(resolver.cache.get_positive_hits()))
    print("  Negative hits:     " + str(resolver.cache.get_negative_hits()))
    print("  Positive misses:   " + str(resolver.cache.get_positive_miss()))
    print("  Negative misses:   " + str(resolver.cache.get_negative_miss()))

print("--------------------CACHE URLS--------------------")
print("--------------------------------------------------")
for url in urls_cache:
    answer_cache = resolver.query(url, 'A')
    # name = dns.name.from_text(url)
    # print(resolver.cache.get((name, dns.rdatatype.A, dns.rdataclass.IN)))
    current_status()

print("--------------------CACHE LRU---------------------")
print("--------------------------------------------------")
# Second Case, checking the refreshing of query
for url in urls_lru:
    answer_lru = resolver.query(url, 'A')
    # name = dns.name.from_text(url)
    # print(resolver.cache.get((name, dns.rdatatype.A, dns.rdataclass.IN)))
    current_status()

print("--------------------CACHE PTR---------------------")
print("--------------------------------------------------")
# Reverse query with caching
for url in urls_rev:
    qname = dns.reversename.from_address(url)
    answer_rev = resolver.query(qname, 'PTR')
    # print(resolver.cache.get((qname, dns.rdatatype.PTR, dns.rdataclass.IN)))
    current_status()
