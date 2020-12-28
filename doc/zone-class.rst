.. _zone-class:

The dns.zone.Zone Class
-----------------------

The ``Zone`` class provides a non-thread-safe implementation of a DNS zone,
as well as a lightweight translation mechanism that allows it to be atomically
updated.  For more complicated transactional needs, or for concurrency, please
use the :py:class:`dns.versioned.Zone` class (described below).

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


The dns.versioned.Zone Class
----------------------------

A versioned Zone is a subclass of ``Zone`` that provides a thread-safe
multiversioned transactional API.  There can be many concurrent
readers, of possibly different versions, and at most one active
writer.  Others cannot see the changes being made by the writer until
it commits.  Versions are immutable once committed.

The read-only parts of the standard zone API continue to be available, and
are equivalent to doing a single-query read-only transaction.  Note that
unless reading is done through a transaction, version stability is not
guaranteed between successive calls.  Attempts to use zone API methods
that directly manipulate the zone, e.g. ``replace_rdataset`` will result
in a ``UseTransaction`` exception.

Transactions are context managers, and are created with ``reader()`` or
``writer()``.  For example:

::

   # Print the SOA serial number of the most recent version
   with zone.reader() as txn:
       rdataset = txn.get('@', 'in', 'soa')
       print('The most recent serial number is', rdataset[0].serial)

   # Write an A RR and increment the SOA serial number to the next value.
   with zone.writer() as txn:
       txn.replace('node1', dns.rdataset.from_text('in', 'a', 300,
                   '10.0.0.1'))
       txn.set_serial()

See below for more information on the ``Transaction`` API.
       
.. autoclass:: dns.versioned.Zone
   :exclude-members: delete_node, delete_rdataset, replace_rdataset
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


The TransactionManager Class
----------------------------

This is the abstract base class of all objects that support transactions.

.. autoclass:: dns.transaction.TransactionManager
   :members:


The Transaction Class
---------------------

.. autoclass:: dns.transaction.Transaction
   :members:
   
