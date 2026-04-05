.. _resolver-nameserver:

The dns.nameserver.Nameserver Classes
-------------------------------------

The :py:class:`dns.nameserver.Nameserver` abstract class represents a remote recursive resolver,
and is used by the stub resolver to answer queries.

.. autoclass:: dns.nameserver.Nameserver
   :members:

The dns.nameserver.Do53Nameserver Class
---------------------------------------

The :py:class:`dns.nameserver.Do53Nameserver` class is a :py:class:`dns.nameserver.Nameserver` class used
to make regular UDP/TCP DNS queries, typically over port 53, to a recursive server.

.. autoclass:: dns.nameserver.Do53Nameserver
   :members:

The dns.nameserver.DoTNameserver Class
---------------------------------------

The :py:class:`dns.nameserver.DoTNameserver` class is a :py:class:`dns.nameserver.Nameserver` class used
to make DNS-over-TLS (DoT) queries to a recursive server.

.. autoclass:: dns.nameserver.DoTNameserver
   :members:

The dns.nameserver.DoHNameserver Class
---------------------------------------

The :py:class:`dns.nameserver.DoHNameserver` class is a :py:class:`dns.nameserver.Nameserver` class used
to make DNS-over-HTTPS (DoH) queries to a recursive server.

.. autoclass:: dns.nameserver.DoHNameserver
   :members:

The dns.nameserver.DoQNameserver Class
---------------------------------------

The :py:class:`dns.nameserver.DoQNameserver` class is a :py:class:`dns.nameserver.Nameserver` class used
to make DNS-over-QUIC (DoQ) queries to a recursive server.

.. autoclass:: dns.nameserver.DoQNameserver
   :members:
