.. _zone-class:

The dns.zone.Zone Class
-----------------------

.. autoclass:: dns.zone.Zone
   :members:
      
   .. attribute:: rdclass

      The zone's rdata class, an ``int``; the default is class IN.

   .. attribute:: origin

      The origin of the zone, a ``dns.name.Name``.

   .. attribute:: nodes
                   
   A dictionary mapping the names of nodes in the zone to the nodes
   themselves.
   
   .. attribute:: relativize

   A ``bool``, which is ``True`` if names in the zone should be relativized.

A ``Zone`` has a class attribute ``node_factory`` which is used to
create new nodes and defaults to ``dns.node.Node``.  ``Zone`` may be
subclassed if a different node factory is desired.
The node factory is a class or callable that returns a subclass of
``dns.node.Node``.
