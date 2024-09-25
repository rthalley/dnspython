.. _zonefile:

The RRSet Reader
----------------

``dns.zonefile.read_rrsets()`` reads one or more RRsets from text format.  It
is designed to be used in situations where you are processing DNS data in
text format, but do not want or need a valid zone.  For example, a DNS registry
web application might want to allow the user to input RRs.

.. autofunction:: dns.zonefile.read_rrsets


Examples
========

Read RRSets with name, TTL, and rdclass forced::

  input = '''
  mx 10 a
  mx 20 b
  ns ns1
  '''
  rrsets = dns.zonefile.read_rrsets(input, name='name', ttl=300)

Read RRSets with name, TTL, rdclass, and rdtype forced::

  input = '''
  10 a
  20 b
  '''
  rrsets = dns.zonefile.read_rrsets(input, name='name', ttl=300, rdtype='mx')

Note that in this case the length of rrsets will always be one.

Read relativized RRsets with unforced rdclass (but which must match
default_rdclass)::

  input = '''
  name1 20 MX 10 a.example.
  name2 30 IN MX 20 b
  '''
  rrsets = dns.zonefile.read_rrsets(input, origin='example', relativize=True,
                                    rdclass=None)

The dns.zonefile.Reader Class
=============================

The ``Reader`` class reads data in DNS zonefile format, or various
restrictions of that format, and converts it to a sequence of operations
in a transaction.

This class is primarily used by ``dns.zone.Zone.from_text()`` and
``dns.zonefile.read_rrsets``, but may be useful for other software which needs
to process the zonefile format.

.. autoclass:: dns.zonefile.Reader
   :members:

