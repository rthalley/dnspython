# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# A derivative of a dnspython VersionedZone and related classes, using a BTreeDict and
# a separate per-version delegation index.  These additions let us
#
# 1) Do efficient CoW versioning (useful for future online updates).
# 2) Maintain sort order
# 3) Allow delegations to be found easily
# 4) Handle glue
# 5) Add Node flags ORIGIN, DELEGATION, and GLUE whenever relevant.  The ORIGIN
#    flag is set at the origin node, the DELEGATION FLAG is set at delegation
#    points, and the GLUE flag is set on nodes beneath delegation points.

import enum
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import cast

import dns.btree
import dns.immutable
import dns.name
import dns.node
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.versioned
import dns.zone


class NodeFlags(enum.IntFlag):
    """Flags that classify a node's role in the zone.

    ``ORIGIN`` is set on the zone origin node.

    ``DELEGATION`` is set at NS delegation points (not at the origin, and not
    on nodes beneath a delegation).

    ``GLUE`` is set on nodes that are proper subdomains of a delegation point.
    """

    ORIGIN = 0x01
    DELEGATION = 0x02
    GLUE = 0x04


class Node(dns.node.Node):
    """A BTree zone node, extending :py:class:`dns.node.Node` with ``flags`` and
    ``id`` fields.

    .. attribute:: flags

       The node's role flags.

       :type: :py:class:`dns.btreezone.NodeFlags`

    .. attribute:: id

       The version id of the last write that touched this node.

       :type: int
    """

    __slots__ = ["flags", "id"]

    def __init__(self, flags: NodeFlags | None = None):
        super().__init__()
        if flags is None:
            # We allow optional flags rather than a default
            # as pyright doesn't like assigning a literal 0
            # to flags.
            flags = NodeFlags(0)
        self.flags = flags
        self.id = 0

    def is_delegation(self):
        """Return ``True`` if this node is an NS delegation point.

        :rtype: bool
        """
        return (self.flags & NodeFlags.DELEGATION) != 0

    def is_glue(self):
        """Return ``True`` if this node is beneath a delegation point.

        :rtype: bool
        """
        return (self.flags & NodeFlags.GLUE) != 0

    def is_origin(self):
        """Return ``True`` if this node is the zone origin.

        :rtype: bool
        """
        return (self.flags & NodeFlags.ORIGIN) != 0

    def is_origin_or_glue(self):
        """Return ``True`` if this node is at the origin or beneath a delegation.

        :rtype: bool
        """
        return (self.flags & (NodeFlags.ORIGIN | NodeFlags.GLUE)) != 0


@dns.immutable.immutable
class ImmutableNode(Node):
    """An immutable :py:class:`dns.btreezone.Node`.

    Mutation methods raise :py:exc:`TypeError`.
    """

    def __init__(self, node: Node):
        super().__init__()
        self.id = node.id
        self.rdatasets = tuple(  # pyright: ignore
            [dns.rdataset.ImmutableRdataset(rds) for rds in node.rdatasets]
        )
        self.flags = node.flags

    def find_rdataset(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
        create: bool = False,
    ) -> dns.rdataset.Rdataset:
        if create:
            raise TypeError("immutable")
        return super().find_rdataset(rdclass, rdtype, covers, False)

    def get_rdataset(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
        create: bool = False,
    ) -> dns.rdataset.Rdataset | None:
        if create:
            raise TypeError("immutable")
        return super().get_rdataset(rdclass, rdtype, covers, False)

    def delete_rdataset(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
    ) -> None:
        raise TypeError("immutable")

    def replace_rdataset(self, replacement: dns.rdataset.Rdataset) -> None:
        raise TypeError("immutable")

    def is_immutable(self) -> bool:
        return True


class Delegations(dns.btree.BTreeSet[dns.name.Name]):
    """A sorted set of delegation-point names.

    Used by :py:class:`dns.btreezone.WritableVersion` and
    :py:class:`dns.btreezone.ImmutableVersion` to efficiently determine
    whether a given name is at or beneath a delegation point.
    """

    def get_delegation(self, name: dns.name.Name) -> tuple[dns.name.Name | None, bool]:
        """Get the delegation applicable to *name*, if it exists.

        :returns: A tuple of the delegation point name and a boolean which is
            ``True`` if *name* is a proper subdomain of the delegation point,
            or ``False`` if it is equal to the delegation point.  If there is
            no applicable delegation, returns ``(None, False)``.
        :rtype: tuple[:py:class:`dns.name.Name` or ``None``, bool]
        """
        cursor = self.cursor()
        cursor.seek(name, before=False)
        prev = cursor.prev()
        if prev is None:
            return None, False
        cut = prev.key()
        reln, _, _ = name.fullcompare(cut)
        is_subdomain = reln == dns.name.NameRelation.SUBDOMAIN
        if is_subdomain or reln == dns.name.NameRelation.EQUAL:
            return cut, is_subdomain
        else:
            return None, False

    def is_glue(self, name: dns.name.Name) -> bool:
        """Is *name* glue, i.e. is it beneath a delegation?"""
        cursor = self.cursor()
        cursor.seek(name, before=False)
        cut, is_subdomain = self.get_delegation(name)
        if cut is None:
            return False
        return is_subdomain


class WritableVersion(dns.zone.WritableVersion):
    """A mutable version of a :py:class:`dns.btreezone.Zone`.

    Extends :py:class:`dns.zone.WritableVersion` with a
    :py:class:`dns.btreezone.Delegations` index and automatic management of
    ``NodeFlags.ORIGIN``, ``NodeFlags.DELEGATION``, and ``NodeFlags.GLUE``
    flags on every node.

    Instances are created internally by the zone; callers should not
    construct them directly.
    """

    def __init__(self, zone: dns.zone.Zone, replacement: bool = False):
        super().__init__(zone, True)
        if not replacement:
            assert isinstance(zone, dns.versioned.Zone)
            version = zone._versions[-1]
            self.nodes: dns.btree.BTreeDict[dns.name.Name, Node] = dns.btree.BTreeDict(
                original=version.nodes  # type: ignore
            )
            self.delegations = Delegations(original=version.delegations)  # type: ignore
        else:
            self.delegations = Delegations()

    def _is_origin(self, name: dns.name.Name) -> bool:
        # Assumes name has already been validated (and thus adjusted to the right
        # relativity too)
        if self.zone.relativize:
            return name == dns.name.empty
        else:
            return name == self.zone.origin

    def _maybe_cow_with_name(
        self, name: dns.name.Name
    ) -> tuple[dns.node.Node, dns.name.Name]:
        node, name = super()._maybe_cow_with_name(name)
        node = cast(Node, node)
        if self._is_origin(name):
            node.flags |= NodeFlags.ORIGIN
        elif self.delegations.is_glue(name):
            node.flags |= NodeFlags.GLUE
        return (node, name)

    def update_glue_flag(self, name: dns.name.Name, is_glue: bool) -> None:
        """Set or clear the ``NodeFlags.GLUE`` flag on all nodes that are
        subdomains of *name*.

        :param name: The delegation-point name whose subtree should be updated.
        :type name: :py:class:`dns.name.Name`
        :param is_glue: ``True`` to set the GLUE flag; ``False`` to clear it.
        :type is_glue: bool
        """
        cursor = self.nodes.cursor()  # pyright: ignore
        cursor.seek(name, False)
        updates = []
        while True:
            elt = cursor.next()
            if elt is None:
                break
            ename = elt.key()
            if not ename.is_subdomain(name):
                break
            node = cast(dns.node.Node, elt.value())
            if ename not in self.changed:
                new_node = self.zone.node_factory()
                new_node.id = self.id  # type: ignore
                new_node.rdatasets.extend(node.rdatasets)
                self.changed.add(ename)
                node = new_node
            assert isinstance(node, Node)
            if is_glue:
                node.flags |= NodeFlags.GLUE
            else:
                node.flags &= ~NodeFlags.GLUE
            # We don't update node here as any insertion could disturb the
            # btree and invalidate our cursor.  We could use the cursor in a
            # with block and avoid this, but it would do a lot of parking and
            # unparking so the deferred update mode may still be better.
            updates.append((ename, node))
        for ename, node in updates:
            self.nodes[ename] = node

    def delete_node(self, name: dns.name.Name) -> None:
        """Delete the node at *name*, updating delegation tracking as needed.

        If *name* is a delegation point, it is removed from the delegations
        index and the GLUE flag is cleared from its subtree.  If *name* does
        not exist in the zone, this method is a no-op.

        :param name: The name of the node to delete.
        :type name: :py:class:`dns.name.Name`
        """
        name = self._validate_name(name)
        node = self.nodes.get(name)
        if node is not None:
            if node.is_delegation():  # pyright: ignore
                self.delegations.discard(name)
                self.update_glue_flag(name, False)
            del self.nodes[name]
            self.changed.add(name)

    def put_rdataset(
        self, name: dns.name.Name, rdataset: dns.rdataset.Rdataset
    ) -> None:
        """Store *rdataset* at *name*, updating delegation flags as needed.

        If *rdataset* is an NS rdataset and *name* is not the origin or beneath
        an existing delegation, the ``DELEGATION`` flag is set on the node and
        the ``GLUE`` flag is set on all nodes in *name*'s subtree.

        :param name: The owner name.
        :type name: :py:class:`dns.name.Name`
        :param rdataset: The rdataset to store.
        :type rdataset: :py:class:`dns.rdataset.Rdataset`
        """
        node, name = self._maybe_cow_with_name(name)
        if (
            rdataset.rdtype == dns.rdatatype.NS
            and not node.is_origin_or_glue()  # type: ignore
        ):
            node.flags |= NodeFlags.DELEGATION  # type: ignore
            if name not in self.delegations:
                self.delegations.add(name)
                self.update_glue_flag(name, True)
        node.replace_rdataset(rdataset)

    def delete_rdataset(
        self,
        name: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
        covers: dns.rdatatype.RdataType,
    ) -> None:
        """Delete the rdataset with *rdtype* and *covers* at *name*.

        If the deleted rdataset was the NS rdataset at a delegation point,
        the ``DELEGATION`` flag is cleared from that node and the ``GLUE``
        flag is cleared from all nodes in its subtree.

        :param name: The owner name.
        :type name: :py:class:`dns.name.Name`
        :param rdtype: The rdata type to remove.
        :type rdtype: :py:class:`dns.rdatatype.RdataType`
        :param covers: The covered type (usually ``dns.rdatatype.NONE``).
        :type covers: :py:class:`dns.rdatatype.RdataType`
        """
        node, name = self._maybe_cow_with_name(name)
        if rdtype == dns.rdatatype.NS and name in self.delegations:  # pyright: ignore
            node.flags &= ~NodeFlags.DELEGATION  # type: ignore
            self.delegations.discard(name)  # pyright: ignore
            self.update_glue_flag(name, False)
        node.delete_rdataset(self.zone.rdclass, rdtype, covers)
        if len(node) == 0:
            del self.nodes[name]


@dataclass(frozen=True)
class Bounds:
    """The result of a :py:meth:`~dns.btreezone.ImmutableVersion.bounds` query.

    Useful for constructing authoritative responses and for on-the-fly DNSSEC
    signatures.

    .. attribute:: name

       The queried name.

       :type: :py:class:`dns.name.Name`

    .. attribute:: left

       The greatest name in the zone that is less than or equal to ``name``.

       :type: :py:class:`dns.name.Name`

    .. attribute:: right

       The least name in the zone that is greater than ``name``, or ``None``
       if ``name`` is greater than every name in the zone.

       :type: :py:class:`dns.name.Name` or ``None``

    .. attribute:: closest_encloser

       The name with the greatest number of labels that is a common ancestor
       of ``name`` and is present in the zone (explicitly or as an implied
       empty non-terminal).

       :type: :py:class:`dns.name.Name`

    .. attribute:: is_equal

       ``True`` if ``name`` is present in the zone (i.e. ``name == left``).

       :type: bool

    .. attribute:: is_delegation

       ``True`` if the left bound is a delegation point.

       :type: bool
    """

    name: dns.name.Name
    left: dns.name.Name
    right: dns.name.Name | None
    closest_encloser: dns.name.Name
    is_equal: bool
    is_delegation: bool

    def __str__(self):
        if self.is_equal:
            op = "="
        else:
            op = "<"
        if self.is_delegation:
            zonecut = " zonecut"
        else:
            zonecut = ""
        return (
            f"{self.left} {op} {self.name} < {self.right}{zonecut}; "
            f"{self.closest_encloser}"
        )


@dns.immutable.immutable
class ImmutableVersion(dns.zone.Version):
    """An immutable, committed version of a :py:class:`dns.btreezone.Zone`.

    In addition to the standard read-only zone API, provides the
    :py:meth:`bounds` method for DNSSEC and authoritative-response support.

    Instances are created internally when a
    :py:class:`dns.btreezone.WritableVersion` is committed; callers should
    not construct them directly.
    """

    def __init__(self, version: dns.zone.Version):
        if not isinstance(version, WritableVersion):
            raise ValueError(
                "a dns.btreezone.ImmutableVersion requires a "
                "dns.btreezone.WritableVersion"
            )
        super().__init__(version.zone, True)
        self.id = version.id
        self.origin = version.origin
        for name in version.changed:
            node = version.nodes.get(name)
            if node:
                version.nodes[name] = ImmutableNode(node)
        self.nodes = cast(MutableMapping[dns.name.Name, dns.node.Node], version.nodes)
        self.nodes.make_immutable()  # type: ignore
        self.delegations = version.delegations
        self.delegations.make_immutable()

    def bounds(self, name: dns.name.Name | str) -> Bounds:
        """Return the bounds of *name* in its zone.

        The bounds information is useful when making an authoritative response, as
        it can be used to determine whether the query name is at or beneath a delegation
        point.  The other data in the :py:class:`dns.btreezone.Bounds` object is useful
        for making on-the-fly DNSSEC signatures.

        The left bound of *name* is *name* itself if it is in the zone, or the greatest
        predecessor which is in the zone.

        The right bound of *name* is the least successor of *name*, or ``None`` if
        no name in the zone is greater than *name*.

        The closest encloser of *name* is *name* itself, if *name* is in the zone;
        otherwise it is the name with the largest number of labels in common with
        *name* that is in the zone, either explicitly or by the implied existence
        of empty non-terminals.

        The *is_equal* field of the result is ``True`` if and only if *name* is equal
        to its left bound.

        The *is_delegation* field of the result is ``True`` if and only if the left
        bound is a delegation point.

        :param name: The name to look up.
        :type name: :py:class:`dns.name.Name` or str
        :rtype: :py:class:`dns.btreezone.Bounds`
        """
        assert self.origin is not None
        # validate the origin because we may need to relativize
        origin = self.zone._validate_name(self.origin)
        name = self.zone._validate_name(name)
        cut, _ = self.delegations.get_delegation(name)
        if cut is not None:
            target = cut
            is_delegation = True
        else:
            target = name
            is_delegation = False
        c = cast(dns.btree.BTreeDict, self.nodes).cursor()
        c.seek(target, False)
        left = c.prev()
        assert left is not None
        c.next()  # skip over left
        while True:
            right = c.next()
            if right is None or not right.value().is_glue():
                break
        left_comparison = left.key().fullcompare(name)
        if right is not None:
            right_key = right.key()
            right_comparison = right_key.fullcompare(name)
        else:
            right_comparison = (
                dns.name.NAMERELN_COMMONANCESTOR,
                -1,
                len(origin),
            )
            right_key = None
        closest_encloser = dns.name.Name(
            name[-max(left_comparison[2], right_comparison[2]) :]
        )
        return Bounds(
            name,
            left.key(),
            right_key,
            closest_encloser,
            left_comparison[0] == dns.name.NameRelation.EQUAL,
            is_delegation,
        )


class Zone(dns.versioned.Zone):
    """A versioned DNS zone backed by a BTree.

    Extends :py:class:`dns.versioned.Zone` with:

    - **Sorted iteration order**: names are always visited in DNS canonical order.
    - **Automatic flag tracking**: every node is tagged with
      :py:class:`dns.btreezone.NodeFlags` (``ORIGIN``, ``DELEGATION``,
      ``GLUE``) as rdatasets are added and removed.
    - **Efficient copy-on-write versioning**: the underlying
      :py:class:`dns.btree.BTreeDict` shares structure between versions so
      that creating a new version is cheap.
    - **DNSSEC / authoritative-response support**: committed versions expose
      :py:meth:`~dns.btreezone.ImmutableVersion.bounds`, which returns the
      nearest names and closest encloser for any query name.
    """

    node_factory: Callable[[], dns.node.Node] = Node
    map_factory: Callable[[], MutableMapping[dns.name.Name, dns.node.Node]] = cast(
        Callable[[], MutableMapping[dns.name.Name, dns.node.Node]],
        dns.btree.BTreeDict[dns.name.Name, Node],
    )
    writable_version_factory: (
        Callable[[dns.zone.Zone, bool], dns.zone.Version] | None
    ) = WritableVersion
    immutable_version_factory: Callable[[dns.zone.Version], dns.zone.Version] | None = (
        ImmutableVersion
    )
