.. _name-class:

The dns.name.Name Class and Predefined Names
--------------------------------------------

.. autoclass:: dns.name.Name
   :members:

   .. attribute:: labels

      A tuple of ``bytes`` in DNS wire format specifying the DNS
      labels in the name, in order from least-significant label
      (i.e. farthest from the origin) to most-significant label.

.. data:: dns.name.root

   The root name, i.e. ``dns.name.Name([b''])``.

.. data:: dns.name.empty

   The empty name, i.e. ``dns.name.Name([])``.
