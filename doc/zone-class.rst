.. _zone-class:

The dns.zone.Zone Class
-----------------------

The :py:class:`dns.zone.Zone` class provides a non-thread-safe implementation
of a DNS zone, as well as a lightweight translation mechanism that allows it
to be atomically updated.  For more complicated transactional needs, or for
concurrency, please use the :py:class:`dns.versioned.Zone` class (described
below).

.. autoclass:: dns.zone.Zone
   :members:

   .. attribute:: rdclass

      The zone's rdata class; the default is class IN.

      :type: :py:class:`dns.rdataclass.RdataClass`

   .. attribute:: origin

      The origin of the zone.

      :type: :py:class:`dns.name.Name`

   .. attribute:: nodes

      A dictionary mapping the names of nodes in the zone to the nodes
      themselves.

   .. attribute:: relativize

      ``True`` if names in the zone should be relativized.

      :type: bool

A :py:class:`dns.zone.Zone` has a class attribute ``node_factory`` which is
used to create new nodes and defaults to :py:class:`dns.node.Node`.
:py:class:`dns.zone.Zone` may be subclassed if a different node factory is
desired.  The node factory is a class or callable that returns a subclass of
:py:class:`dns.node.Node`.

.. autoclass:: dns.zone.ZoneStyle
   :members:
   :inherited-members:

The dns.versioned.Zone Class
----------------------------

A :py:class:`dns.versioned.Zone` is a subclass of :py:class:`dns.zone.Zone`
that provides a thread-safe multiversioned transactional API.  There can be
many concurrent readers, of possibly different versions, and at most one
active writer.  Others cannot see the changes being made by the writer until
it commits.  Versions are immutable once committed.

The read-only parts of the standard zone API continue to be available, and
are equivalent to doing a single-query read-only transaction.  Note that
unless reading is done through a transaction, version stability is not
guaranteed between successive calls.  Attempts to use zone API methods
that directly manipulate the zone, e.g.
:py:meth:`dns.zone.Zone.replace_rdataset`, will result in a
:py:exc:`dns.versioned.UseTransaction` exception.

Transactions are context managers, and are created with
:py:meth:`dns.versioned.Zone.reader` or
:py:meth:`dns.versioned.Zone.writer`.  For example:

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

See below for more information on the :py:class:`dns.transaction.Transaction`
API.

.. autoexception:: dns.versioned.UseTransaction

.. autoclass:: dns.versioned.Zone
   :exclude-members: delete_node, delete_rdataset, replace_rdataset
   :members:

   .. attribute:: rdclass

      The zone's rdata class; the default is class IN.

      :type: :py:class:`dns.rdataclass.RdataClass`

   .. attribute:: origin

      The origin of the zone.

      :type: :py:class:`dns.name.Name`

   .. attribute:: nodes

      A dictionary mapping the names of nodes in the zone to the nodes
      themselves.

   .. attribute:: relativize

      ``True`` if names in the zone should be relativized.

      :type: bool


The Version Classes
-------------------

.. autoclass:: dns.zone.Version
   :members:

.. autoclass:: dns.zone.WritableVersion
   :members:

.. autoclass:: dns.zone.ImmutableVersion
   :members:

.. autoclass:: dns.zone.VersionedNode
   :members:

.. autoclass:: dns.zone.ImmutableVersionedNode
   :members:


The Zone Transaction Class
--------------------------

.. autoclass:: dns.zone.Transaction
   :members:


The TransactionManager Class
----------------------------

This is the abstract base class of all objects that support transactions.

.. autoclass:: dns.transaction.TransactionManager
   :members:


The Transaction Class
---------------------

.. autoclass:: dns.transaction.Transaction
   :members:

.. autoexception:: dns.transaction.AlreadyEnded

.. autoexception:: dns.transaction.DeleteNotExact

.. autoexception:: dns.transaction.ReadOnly


The dns.btreezone.Zone Class
----------------------------

:py:class:`dns.btreezone.Zone` is a subclass of :py:class:`dns.versioned.Zone`
backed by a :py:class:`dns.btree.BTreeDict`.  It maintains names in DNS
canonical (sorted) order, automatically tracks
:py:class:`dns.btreezone.NodeFlags` (``ORIGIN``, ``DELEGATION``, and ``GLUE``)
on every node as rdatasets are added or removed, and shares BTree structure
between versions for efficient copy-on-write behaviour.

Committed versions expose :py:meth:`~dns.btreezone.ImmutableVersion.bounds`,
which returns the nearest names and closest encloser for any query name.  This
information is useful both for constructing authoritative responses and for
generating on-the-fly DNSSEC signatures.

.. autoclass:: dns.btreezone.Zone
   :members:

The btreezone Node Classes
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dns.btreezone.NodeFlags
   :members:
   :inherited-members:

.. autoclass:: dns.btreezone.Node
   :members:

.. autoclass:: dns.btreezone.ImmutableNode
   :members:

The btreezone Version Classes
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: dns.btreezone.Delegations
   :members:

.. autoclass:: dns.btreezone.WritableVersion
   :members:

.. autoclass:: dns.btreezone.ImmutableVersion
   :members:
   :inherited-members:

.. autoclass:: dns.btreezone.Bounds
   :members:

