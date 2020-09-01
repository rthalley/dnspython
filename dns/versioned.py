# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""DNS Versioned Zones."""

import collections
try:
    import threading as _threading
except ImportError:  # pragma: no cover
    import dummy_threading as _threading    # type: ignore

import dns.exception
import dns.immutable
import dns.name
import dns.node
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rdtypes.ANY.SOA
import dns.transaction
import dns.zone


class UseTransaction(dns.exception.DNSException):
    """To alter a versioned zone, use a transaction."""


class Version:
    def __init__(self, zone, id):
        self.zone = zone
        self.id = id
        self.nodes = {}

    def _validate_name(self, name):
        if name.is_absolute():
            if not name.is_subdomain(self.zone.origin):
                raise KeyError("name is not a subdomain of the zone origin")
            if self.zone.relativize:
                name = name.relativize(self.origin)
        return name

    def get_node(self, name):
        name = self._validate_name(name)
        return self.nodes.get(name)

    def get_rdataset(self, name, rdtype, covers):
        node = self.get_node(name)
        if node is None:
            return None
        return node.get_rdataset(self.zone.rdclass, rdtype, covers)

    def items(self):
        return self.nodes.items()  # pylint: disable=dict-items-not-iterating


class WritableVersion(Version):
    def __init__(self, zone, replacement=False):
        # The zone._versions_lock must be held by our caller.
        if len(zone._versions) > 0:
            id = zone._versions[-1].id + 1
        else:
            id = 1
        super().__init__(zone, id)
        if not replacement:
            # We copy the map, because that gives us a simple and thread-safe
            # way of doing versions, and we have a garbage collector to help
            # us.  We only make new node objects if we actually change the
            # node.
            self.nodes.update(zone.nodes)
        # We have to copy the zone origin as it may be None in the first
        # version, and we don't want to mutate the zone until we commit.
        self.origin = zone.origin
        self.changed = set()

    def _maybe_cow(self, name):
        name = self._validate_name(name)
        node = self.nodes.get(name)
        if node is None or node.id != self.id:
            new_node = self.zone.node_factory()
            new_node.id = self.id
            if node is not None:
                # moo!  copy on write!
                new_node.rdatasets.extend(node.rdatasets)
            self.nodes[name] = new_node
            self.changed.add(name)
            return new_node
        else:
            return node

    def delete_node(self, name):
        name = self._validate_name(name)
        if name in self.nodes:
            del self.nodes[name]
            self.changed.add(name)

    def put_rdataset(self, name, rdataset):
        node = self._maybe_cow(name)
        node.replace_rdataset(rdataset)

    def delete_rdataset(self, name, rdtype, covers):
        node = self._maybe_cow(name)
        node.delete_rdataset(self.zone.rdclass, rdtype, covers)
        if len(node) == 0:
            del self.nodes[name]


@dns.immutable.immutable
class ImmutableVersion(Version):
    def __init__(self, version):
        # We tell super() that it's a replacement as we don't want it
        # to copy the nodes, as we're about to do that with an
        # immutable Dict.
        super().__init__(version.zone, True)
        # set the right id!
        self.id = version.id
        # Make changed nodes immutable
        for name in version.changed:
            node = version.nodes.get(name)
            # it might not exist if we deleted it in the version
            if node:
                version.nodes[name] = ImmutableNode(node)
        self.nodes = dns.immutable.Dict(version.nodes, True)


# A node with a version id.

class Node(dns.node.Node):
    __slots__ = ['id']

    def __init__(self):
        super().__init__()
        # A proper id will get set by the Version
        self.id = 0


@dns.immutable.immutable
class ImmutableNode(Node):
    __slots__ = ['id']

    def __init__(self, node):
        super().__init__()
        self.id = node.id
        self.rdatasets = tuple(
            [dns.rdataset.ImmutableRdataset(rds) for rds in node.rdatasets]
        )

    def find_rdataset(self, rdclass, rdtype, covers=dns.rdatatype.NONE,
                      create=False):
        if create:
            raise TypeError("immutable")
        return super().find_rdataset(rdclass, rdtype, covers, False)

    def get_rdataset(self, rdclass, rdtype, covers=dns.rdatatype.NONE,
                     create=False):
        if create:
            raise TypeError("immutable")
        return super().get_rdataset(rdclass, rdtype, covers, False)

    def delete_rdataset(self, rdclass, rdtype, covers=dns.rdatatype.NONE):
        raise TypeError("immutable")

    def replace_rdataset(self, replacement):
        raise TypeError("immutable")


class Zone(dns.zone.Zone):

    __slots__ = ['_versions', '_versions_lock', '_write_txn',
                 '_write_waiters', '_write_event', '_pruning_policy',
                 '_readers']

    node_factory = Node

    def __init__(self, origin, rdclass=dns.rdataclass.IN, relativize=True,
                 pruning_policy=None):
        """Initialize a versioned zone object.

        *origin* is the origin of the zone.  It may be a ``dns.name.Name``,
        a ``str``, or ``None``.  If ``None``, then the zone's origin will
        be set by the first ``$ORIGIN`` line in a zone file.

        *rdclass*, an ``int``, the zone's rdata class; the default is class IN.

        *relativize*, a ``bool``, determine's whether domain names are
        relativized to the zone's origin.  The default is ``True``.

        *pruning policy*, a function taking a `Version` and returning
        a `bool`, or `None`.  Should the version be pruned?  If `None`,
        the default policy, which retains one version is used.
        """
        super().__init__(origin, rdclass, relativize)
        self._versions = collections.deque()
        self._version_lock = _threading.Lock()
        if pruning_policy is None:
            self._pruning_policy = self._default_pruning_policy
        else:
            self._pruning_policy = pruning_policy
        self._write_txn = None
        self._write_event = None
        self._write_waiters = collections.deque()
        self._readers = set()
        self._commit_version_unlocked(None, WritableVersion(self), origin)

    def reader(self, id=None, serial=None):  # pylint: disable=arguments-differ
        if id is not None and serial is not None:
            raise ValueError('cannot specify both id and serial')
        with self._version_lock:
            if id is not None:
                version = None
                for v in reversed(self._versions):
                    if v.id == id:
                        version = v
                        break
                if version is None:
                    raise KeyError('version not found')
            elif serial is not None:
                if self.relativize:
                    oname = dns.name.empty
                else:
                    oname = self.origin
                version = None
                for v in reversed(self._versions):
                    n = v.nodes.get(oname)
                    if n:
                        rds = n.get_rdataset(self.rdclass, dns.rdatatype.SOA)
                        if rds and rds[0].serial == serial:
                            version = v
                            break
                if version is None:
                    raise KeyError('serial not found')
            else:
                version = self._versions[-1]
            txn = Transaction(self, False, version)
            self._readers.add(txn)
            return txn

    def writer(self, replacement=False):
        event = None
        while True:
            with self._version_lock:
                # Checking event == self._write_event ensures that either
                # no one was waiting before we got lucky and found no write
                # txn, or we were the one who was waiting and got woken up.
                # This prevents "taking cuts" when creating a write txn.
                if self._write_txn is None and event == self._write_event:
                    # Creating the transaction defers version setup
                    # (i.e.  copying the nodes dictionary) until we
                    # give up the lock, so that we hold the lock as
                    # short a time as possible.  This is why we call
                    # _setup_version() below.
                    self._write_txn = Transaction(self, replacement)
                    # give up our exclusive right to make a Transaction
                    self._write_event = None
                    break
                # Someone else is writing already, so we will have to
                # wait, but we want to do the actual wait outside the
                # lock.
                event = _threading.Event()
                self._write_waiters.append(event)
            # wait (note we gave up the lock!)
            #
            # We only wake one sleeper at a time, so it's important
            # that no event waiter can exit this method (e.g. via
            # cancelation) without returning a transaction or waking
            # someone else up.
            #
            # This is not a problem with Threading module threads as
            # they cannot be canceled, but could be an issue with trio
            # or curio tasks when we do the async version of writer().
            # I.e. we'd need to do something like:
            #
            # try:
            #     event.wait()
            # except trio.Cancelled:
            #     with self._version_lock:
            #         self._maybe_wakeup_one_waiter_unlocked()
            #     raise
            #
            event.wait()
        # Do the deferred version setup.
        self._write_txn._setup_version()
        return self._write_txn

    def _maybe_wakeup_one_waiter_unlocked(self):
        if len(self._write_waiters) > 0:
            self._write_event = self._write_waiters.popleft()
            self._write_event.set()

    # pylint: disable=unused-argument
    def _default_pruning_policy(self, zone, version):
        return True
    # pylint: enable=unused-argument

    def _prune_versions_unlocked(self):
        assert len(self._versions) > 0
        # Don't ever prune a version greater than or equal to one that
        # a reader has open.  This pins versions in memory while the
        # reader is open, and importantly lets the reader open a txn on
        # a successor version (e.g. if generating an IXFR).
        #
        # Note our definition of least_kept also ensures we do not try to
        # delete the greatest version.
        if len(self._readers) > 0:
            least_kept = min(txn.version.id for txn in self._readers)
        else:
            least_kept = self._versions[-1].id
        while self._versions[0].id < least_kept and \
              self._pruning_policy(self, self._versions[0]):
            self._versions.popleft()

    def set_max_versions(self, max_versions):
        """Set a pruning policy that retains up to the specified number
        of versions
        """
        if max_versions is not None and max_versions < 1:
            raise ValueError('max versions must be at least 1')
        if max_versions is None:
            def policy(*_):
                return False
        else:
            def policy(zone, _):
                return len(zone._versions) > max_versions
        self.set_pruning_policy(policy)

    def set_pruning_policy(self, policy):
        """Set the pruning policy for the zone.

        The *policy* function takes a `Version` and returns `True` if
        the version should be pruned, and `False` otherwise.  `None`
        may also be specified for policy, in which case the default policy
        is used.

        Pruning checking proceeds from the least version and the first
        time the function returns `False`, the checking stops.  I.e. the
        retained versions are always a consecutive sequence.
        """
        if policy is None:
            policy = self._default_pruning_policy
        with self._version_lock:
            self._pruning_policy = policy
            self._prune_versions_unlocked()

    def _end_read(self, txn):
        with self._version_lock:
            self._readers.remove(txn)
            self._prune_versions_unlocked()

    def _end_write_unlocked(self, txn):
        assert self._write_txn == txn
        self._write_txn = None
        self._maybe_wakeup_one_waiter_unlocked()

    def _end_write(self, txn):
        with self._version_lock:
            self._end_write_unlocked(txn)

    def _commit_version_unlocked(self, txn, version, origin):
        self._versions.append(version)
        self._prune_versions_unlocked()
        self.nodes = version.nodes
        if self.origin is None:
            self.origin = origin
        # txn can be None in __init__ when we make the empty version.
        if txn is not None:
            self._end_write_unlocked(txn)

    def _commit_version(self, txn, version, origin):
        with self._version_lock:
            self._commit_version_unlocked(txn, version, origin)

    def find_node(self, name, create=False):
        if create:
            raise UseTransaction
        return super().find_node(name)

    def delete_node(self, name):
        raise UseTransaction

    def find_rdataset(self, name, rdtype, covers=dns.rdatatype.NONE,
                      create=False):
        if create:
            raise UseTransaction
        rdataset = super().find_rdataset(name, rdtype, covers)
        return dns.rdataset.ImmutableRdataset(rdataset)

    def get_rdataset(self, name, rdtype, covers=dns.rdatatype.NONE,
                     create=False):
        if create:
            raise UseTransaction
        rdataset = super().get_rdataset(name, rdtype, covers)
        return dns.rdataset.ImmutableRdataset(rdataset)

    def delete_rdataset(self, name, rdtype, covers=dns.rdatatype.NONE):
        raise UseTransaction

    def replace_rdataset(self, name, replacement):
        raise UseTransaction


class Transaction(dns.transaction.Transaction):

    def __init__(self, zone, replacement, version=None):
        read_only = version is not None
        super().__init__(zone, replacement, read_only)
        self.version = version

    @property
    def zone(self):
        return self.manager

    def _setup_version(self):
        assert self.version is None
        self.version = WritableVersion(self.zone, self.replacement)

    def _get_rdataset(self, name, rdtype, covers):
        return self.version.get_rdataset(name, rdtype, covers)

    def _put_rdataset(self, name, rdataset):
        assert not self.read_only
        self.version.put_rdataset(name, rdataset)

    def _delete_name(self, name):
        assert not self.read_only
        self.version.delete_node(name)

    def _delete_rdataset(self, name, rdtype, covers):
        assert not self.read_only
        self.version.delete_rdataset(name, rdtype, covers)

    def _name_exists(self, name):
        return self.version.get_node(name) is not None

    def _changed(self):
        if self.read_only:
            return False
        else:
            return len(self.version.changed) > 0

    def _end_transaction(self, commit):
        if self.read_only:
            self.zone._end_read(self)
        elif commit and len(self.version.changed) > 0:
            self.zone._commit_version(self, ImmutableVersion(self.version),
                                      self.version.origin)
        else:
            # rollback
            self.zone._end_write(self)

    def _set_origin(self, origin):
        if self.version.origin is None:
            self.version.origin = origin

    def _iterate_rdatasets(self):
        for (name, node) in self.version.items():
            for rdataset in node:
                yield (name, rdataset)
