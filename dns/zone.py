# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""DNS Zones."""

import contextlib
import io
import os

import dns.exception
import dns.name
import dns.node
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.tokenizer
import dns.transaction
import dns.ttl
import dns.grange
import dns.zonefile


class BadZone(dns.exception.DNSException):

    """The DNS zone is malformed."""


class NoSOA(BadZone):

    """The DNS zone has no SOA RR at its origin."""


class NoNS(BadZone):

    """The DNS zone has no NS RRset at its origin."""


class UnknownOrigin(BadZone):

    """The DNS zone's origin is unknown."""


class Zone(dns.transaction.TransactionManager):

    """A DNS zone.

    A ``Zone`` is a mapping from names to nodes.  The zone object may be
    treated like a Python dictionary, e.g. ``zone[name]`` will retrieve
    the node associated with that name.  The *name* may be a
    ``dns.name.Name object``, or it may be a string.  In either case,
    if the name is relative it is treated as relative to the origin of
    the zone.
    """

    node_factory = dns.node.Node

    __slots__ = ['rdclass', 'origin', 'nodes', 'relativize']

    def __init__(self, origin, rdclass=dns.rdataclass.IN, relativize=True):
        """Initialize a zone object.

        *origin* is the origin of the zone.  It may be a ``dns.name.Name``,
        a ``str``, or ``None``.  If ``None``, then the zone's origin will
        be set by the first ``$ORIGIN`` line in a zone file.

        *rdclass*, an ``int``, the zone's rdata class; the default is class IN.

        *relativize*, a ``bool``, determine's whether domain names are
        relativized to the zone's origin.  The default is ``True``.
        """

        if origin is not None:
            if isinstance(origin, str):
                origin = dns.name.from_text(origin)
            elif not isinstance(origin, dns.name.Name):
                raise ValueError("origin parameter must be convertible to a "
                                 "DNS name")
            if not origin.is_absolute():
                raise ValueError("origin parameter must be an absolute name")
        self.origin = origin
        self.rdclass = rdclass
        self.nodes = {}
        self.relativize = relativize

    def __eq__(self, other):
        """Two zones are equal if they have the same origin, class, and
        nodes.

        Returns a ``bool``.
        """

        if not isinstance(other, Zone):
            return False
        if self.rdclass != other.rdclass or \
           self.origin != other.origin or \
           self.nodes != other.nodes:
            return False
        return True

    def __ne__(self, other):
        """Are two zones not equal?

        Returns a ``bool``.
        """

        return not self.__eq__(other)

    def _validate_name(self, name):
        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        elif not isinstance(name, dns.name.Name):
            raise KeyError("name parameter must be convertible to a DNS name")
        if name.is_absolute():
            if not name.is_subdomain(self.origin):
                raise KeyError(
                    "name parameter must be a subdomain of the zone origin")
            if self.relativize:
                name = name.relativize(self.origin)
        return name

    def __getitem__(self, key):
        key = self._validate_name(key)
        return self.nodes[key]

    def __setitem__(self, key, value):
        key = self._validate_name(key)
        self.nodes[key] = value

    def __delitem__(self, key):
        key = self._validate_name(key)
        del self.nodes[key]

    def __iter__(self):
        return self.nodes.__iter__()

    def keys(self):
        return self.nodes.keys()  # pylint: disable=dict-keys-not-iterating

    def values(self):
        return self.nodes.values()  # pylint: disable=dict-values-not-iterating

    def items(self):
        return self.nodes.items()  # pylint: disable=dict-items-not-iterating

    def get(self, key):
        key = self._validate_name(key)
        return self.nodes.get(key)

    def __contains__(self, other):
        return other in self.nodes

    def find_node(self, name, create=False):
        """Find a node in the zone, possibly creating it.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.node.Node``.
        """

        name = self._validate_name(name)
        node = self.nodes.get(name)
        if node is None:
            if not create:
                raise KeyError
            node = self.node_factory()
            self.nodes[name] = node
        return node

    def get_node(self, name, create=False):
        """Get a node in the zone, possibly creating it.

        This method is like ``find_node()``, except it returns None instead
        of raising an exception if the node does not exist and creation
        has not been requested.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.node.Node`` or ``None``.
        """

        try:
            node = self.find_node(name, create)
        except KeyError:
            node = None
        return node

    def delete_node(self, name):
        """Delete the specified node if it exists.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        It is not an error if the node does not exist.
        """

        name = self._validate_name(name)
        if name in self.nodes:
            del self.nodes[name]

    def find_rdataset(self, name, rdtype, covers=dns.rdatatype.NONE,
                      create=False):
        """Look for an rdataset with the specified name and type in the zone,
        and return an rdataset encapsulating it.

        The rdataset returned is not a copy; changes to it will change
        the zone.

        KeyError is raised if the name or type are not found.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, an ``int`` or ``str``, the rdata type desired.

        *covers*, an ``int`` or ``str`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.rdataset.Rdataset``.
        """

        name = self._validate_name(name)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        if covers is not None:
            covers = dns.rdatatype.RdataType.make(covers)
        node = self.find_node(name, create)
        return node.find_rdataset(self.rdclass, rdtype, covers, create)

    def get_rdataset(self, name, rdtype, covers=dns.rdatatype.NONE,
                     create=False):
        """Look for an rdataset with the specified name and type in the zone.

        This method is like ``find_rdataset()``, except it returns None instead
        of raising an exception if the rdataset does not exist and creation
        has not been requested.

        The rdataset returned is not a copy; changes to it will change
        the zone.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, an ``int`` or ``str``, the rdata type desired.

        *covers*, an ``int`` or ``str`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.rdataset.Rdataset`` or ``None``.
        """

        try:
            rdataset = self.find_rdataset(name, rdtype, covers, create)
        except KeyError:
            rdataset = None
        return rdataset

    def delete_rdataset(self, name, rdtype, covers=dns.rdatatype.NONE):
        """Delete the rdataset matching *rdtype* and *covers*, if it
        exists at the node specified by *name*.

        It is not an error if the node does not exist, or if there is no
        matching rdataset at the node.

        If the node has no rdatasets after the deletion, it will itself
        be deleted.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, an ``int`` or ``str``, the rdata type desired.

        *covers*, an ``int`` or ``str`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.
        """

        name = self._validate_name(name)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        if covers is not None:
            covers = dns.rdatatype.RdataType.make(covers)
        node = self.get_node(name)
        if node is not None:
            node.delete_rdataset(self.rdclass, rdtype, covers)
            if len(node) == 0:
                self.delete_node(name)

    def replace_rdataset(self, name, replacement):
        """Replace an rdataset at name.

        It is not an error if there is no rdataset matching I{replacement}.

        Ownership of the *replacement* object is transferred to the zone;
        in other words, this method does not store a copy of *replacement*
        at the node, it stores *replacement* itself.

        If the node does not exist, it is created.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *replacement*, a ``dns.rdataset.Rdataset``, the replacement rdataset.
        """

        if replacement.rdclass != self.rdclass:
            raise ValueError('replacement.rdclass != zone.rdclass')
        node = self.find_node(name, True)
        node.replace_rdataset(replacement)

    def find_rrset(self, name, rdtype, covers=dns.rdatatype.NONE):
        """Look for an rdataset with the specified name and type in the zone,
        and return an RRset encapsulating it.

        This method is less efficient than the similar
        ``find_rdataset()`` because it creates an RRset instead of
        returning the matching rdataset.  It may be more convenient
        for some uses since it returns an object which binds the owner
        name to the rdataset.

        This method may not be used to create new nodes or rdatasets;
        use ``find_rdataset`` instead.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, an ``int`` or ``str``, the rdata type desired.

        *covers*, an ``int`` or ``str`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.rrset.RRset`` or ``None``.
        """

        name = self._validate_name(name)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        if covers is not None:
            covers = dns.rdatatype.RdataType.make(covers)
        rdataset = self.nodes[name].find_rdataset(self.rdclass, rdtype, covers)
        rrset = dns.rrset.RRset(name, self.rdclass, rdtype, covers)
        rrset.update(rdataset)
        return rrset

    def get_rrset(self, name, rdtype, covers=dns.rdatatype.NONE):
        """Look for an rdataset with the specified name and type in the zone,
        and return an RRset encapsulating it.

        This method is less efficient than the similar ``get_rdataset()``
        because it creates an RRset instead of returning the matching
        rdataset.  It may be more convenient for some uses since it
        returns an object which binds the owner name to the rdataset.

        This method may not be used to create new nodes or rdatasets;
        use ``get_rdataset()`` instead.

        *name*: the name of the node to find.
        The value may be a ``dns.name.Name`` or a ``str``.  If absolute, the
        name must be a subdomain of the zone's origin.  If ``zone.relativize``
        is ``True``, then the name will be relativized.

        *rdtype*, an ``int`` or ``str``, the rdata type desired.

        *covers*, an ``int`` or ``str`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.

        *create*, a ``bool``.  If true, the node will be created if it does
        not exist.

        Raises ``KeyError`` if the name is not known and create was
        not specified, or if the name was not a subdomain of the origin.

        Returns a ``dns.rrset.RRset`` or ``None``.
        """

        try:
            rrset = self.find_rrset(name, rdtype, covers)
        except KeyError:
            rrset = None
        return rrset

    def iterate_rdatasets(self, rdtype=dns.rdatatype.ANY,
                          covers=dns.rdatatype.NONE):
        """Return a generator which yields (name, rdataset) tuples for
        all rdatasets in the zone which have the specified *rdtype*
        and *covers*.  If *rdtype* is ``dns.rdatatype.ANY``, the default,
        then all rdatasets will be matched.

        *rdtype*, an ``int`` or ``str``, the rdata type desired.

        *covers*, an ``int`` or ``str`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.
        """

        rdtype = dns.rdatatype.RdataType.make(rdtype)
        if covers is not None:
            covers = dns.rdatatype.RdataType.make(covers)
        for (name, node) in self.items():
            for rds in node:
                if rdtype == dns.rdatatype.ANY or \
                   (rds.rdtype == rdtype and rds.covers == covers):
                    yield (name, rds)

    def iterate_rdatas(self, rdtype=dns.rdatatype.ANY,
                       covers=dns.rdatatype.NONE):
        """Return a generator which yields (name, ttl, rdata) tuples for
        all rdatas in the zone which have the specified *rdtype*
        and *covers*.  If *rdtype* is ``dns.rdatatype.ANY``, the default,
        then all rdatas will be matched.

        *rdtype*, an ``int`` or ``str``, the rdata type desired.

        *covers*, an ``int`` or ``str`` or ``None``, the covered type.
        Usually this value is ``dns.rdatatype.NONE``, but if the
        rdtype is ``dns.rdatatype.SIG`` or ``dns.rdatatype.RRSIG``,
        then the covers value will be the rdata type the SIG/RRSIG
        covers.  The library treats the SIG and RRSIG types as if they
        were a family of types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).
        This makes RRSIGs much easier to work with than if RRSIGs
        covering different rdata types were aggregated into a single
        RRSIG rdataset.
        """

        rdtype = dns.rdatatype.RdataType.make(rdtype)
        if covers is not None:
            covers = dns.rdatatype.RdataType.make(covers)
        for (name, node) in self.items():
            for rds in node:
                if rdtype == dns.rdatatype.ANY or \
                   (rds.rdtype == rdtype and rds.covers == covers):
                    for rdata in rds:
                        yield (name, rds.ttl, rdata)

    def to_file(self, f, sorted=True, relativize=True, nl=None,
                want_comments=False):
        """Write a zone to a file.

        *f*, a file or `str`.  If *f* is a string, it is treated
        as the name of a file to open.

        *sorted*, a ``bool``.  If True, the default, then the file
        will be written with the names sorted in DNSSEC order from
        least to greatest.  Otherwise the names will be written in
        whatever order they happen to have in the zone's dictionary.

        *relativize*, a ``bool``.  If True, the default, then domain
        names in the output will be relativized to the zone's origin
        if possible.

        *nl*, a ``str`` or None.  The end of line string.  If not
        ``None``, the output will use the platform's native
        end-of-line marker (i.e. LF on POSIX, CRLF on Windows).

        *want_comments*, a ``bool``.  If ``True``, emit end-of-line comments
        as part of writing the file.  If ``False``, the default, do not
        emit them.
        """

        with contextlib.ExitStack() as stack:
            if isinstance(f, str):
                f = stack.enter_context(open(f, 'wb'))

            # must be in this way, f.encoding may contain None, or even
            # attribute may not be there
            file_enc = getattr(f, 'encoding', None)
            if file_enc is None:
                file_enc = 'utf-8'

            if nl is None:
                # binary mode, '\n' is not enough
                nl_b = os.linesep.encode(file_enc)
                nl = '\n'
            elif isinstance(nl, str):
                nl_b = nl.encode(file_enc)
            else:
                nl_b = nl
                nl = nl.decode()

            if sorted:
                names = list(self.keys())
                names.sort()
            else:
                names = self.keys()
            for n in names:
                l = self[n].to_text(n, origin=self.origin,
                                    relativize=relativize,
                                    want_comments=want_comments)
                l_b = l.encode(file_enc)

                try:
                    f.write(l_b)
                    f.write(nl_b)
                except TypeError:  # textual mode
                    f.write(l)
                    f.write(nl)

    def to_text(self, sorted=True, relativize=True, nl=None,
                want_comments=False):
        """Return a zone's text as though it were written to a file.

        *sorted*, a ``bool``.  If True, the default, then the file
        will be written with the names sorted in DNSSEC order from
        least to greatest.  Otherwise the names will be written in
        whatever order they happen to have in the zone's dictionary.

        *relativize*, a ``bool``.  If True, the default, then domain
        names in the output will be relativized to the zone's origin
        if possible.

        *nl*, a ``str`` or None.  The end of line string.  If not
        ``None``, the output will use the platform's native
        end-of-line marker (i.e. LF on POSIX, CRLF on Windows).

        *want_comments*, a ``bool``.  If ``True``, emit end-of-line comments
        as part of writing the file.  If ``False``, the default, do not
        emit them.

        Returns a ``str``.
        """
        temp_buffer = io.StringIO()
        self.to_file(temp_buffer, sorted, relativize, nl, want_comments)
        return_value = temp_buffer.getvalue()
        temp_buffer.close()
        return return_value

    def check_origin(self):
        """Do some simple checking of the zone's origin.

        Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

        Raises ``dns.zone.NoNS`` if there is no NS RRset.

        Raises ``KeyError`` if there is no origin node.
        """
        if self.relativize:
            name = dns.name.empty
        else:
            name = self.origin
        if self.get_rdataset(name, dns.rdatatype.SOA) is None:
            raise NoSOA
        if self.get_rdataset(name, dns.rdatatype.NS) is None:
            raise NoNS

    # TransactionManager methods

    def reader(self):
        return Transaction(self, False, True)

    def writer(self, replacement=False):
        return Transaction(self, replacement, False)

    def origin_information(self):
        if self.relativize:
            effective = dns.name.empty
        else:
            effective = self.origin
        return (self.origin, self.relativize, effective)

    def get_class(self):
        return self.rdclass


class Transaction(dns.transaction.Transaction):

    _deleted_rdataset = dns.rdataset.Rdataset(dns.rdataclass.ANY,
                                              dns.rdatatype.ANY)

    def __init__(self, zone, replacement, read_only):
        super().__init__(zone, replacement, read_only)
        self.rdatasets = {}

    @property
    def zone(self):
        return self.manager

    def _get_rdataset(self, name, rdtype, covers):
        rdataset = self.rdatasets.get((name, rdtype, covers))
        if rdataset is self._deleted_rdataset:
            return None
        elif rdataset is None:
            rdataset = self.zone.get_rdataset(name, rdtype, covers)
        return rdataset

    def _put_rdataset(self, name, rdataset):
        assert not self.read_only
        self.zone._validate_name(name)
        self.rdatasets[(name, rdataset.rdtype, rdataset.covers)] = rdataset

    def _delete_name(self, name):
        assert not self.read_only
        # First remove any changes involving the name
        remove = []
        for key in self.rdatasets:
            if key[0] == name:
                remove.append(key)
        if len(remove) > 0:
            for key in remove:
                del self.rdatasets[key]
        # Next add deletion records for any rdatasets matching the
        # name in the zone
        node = self.zone.get_node(name)
        if node is not None:
            for rdataset in node.rdatasets:
                self.rdatasets[(name, rdataset.rdtype, rdataset.covers)] = \
                    self._deleted_rdataset

    def _delete_rdataset(self, name, rdtype, covers):
        assert not self.read_only
        try:
            del self.rdatasets[(name, rdtype, covers)]
        except KeyError:
            pass
        rdataset = self.zone.get_rdataset(name, rdtype, covers)
        if rdataset is not None:
            self.rdatasets[(name, rdataset.rdtype, rdataset.covers)] = \
                self._deleted_rdataset

    def _name_exists(self, name):
        for key, rdataset in self.rdatasets.items():
            if key[0] == name:
                if rdataset != self._deleted_rdataset:
                    return True
                else:
                    return None
        self.zone._validate_name(name)
        if self.zone.get_node(name):
            return True
        return False

    def _changed(self):
        if self.read_only:
            return False
        else:
            return len(self.rdatasets) > 0

    def _end_transaction(self, commit):
        if commit and self._changed():
            for (name, rdtype, covers), rdataset in \
                self.rdatasets.items():
                if rdataset is self._deleted_rdataset:
                    self.zone.delete_rdataset(name, rdtype, covers)
                else:
                    self.zone.replace_rdataset(name, rdataset)

    def _set_origin(self, origin):
        if self.zone.origin is None:
            self.zone.origin = origin

    def _iterate_rdatasets(self):
        # Expensive but simple!  Use a versioned zone for efficient txn
        # iteration.
        rdatasets = {}
        for (name, rdataset) in self.zone.iterate_rdatasets():
            rdatasets[(name, rdataset.rdtype, rdataset.covers)] = rdataset
        rdatasets.update(self.rdatasets)
        for (name, _, _), rdataset in rdatasets.items():
            yield (name, rdataset)


def from_text(text, origin=None, rdclass=dns.rdataclass.IN,
              relativize=True, zone_factory=Zone, filename=None,
              allow_include=False, check_origin=True, idna_codec=None):
    """Build a zone object from a zone file format string.

    *text*, a ``str``, the zone file format input.

    *origin*, a ``dns.name.Name``, a ``str``, or ``None``.  The origin
    of the zone; if not specified, the first ``$ORIGIN`` statement in the
    zone file will determine the origin of the zone.

    *rdclass*, an ``int``, the zone's rdata class; the default is class IN.

    *relativize*, a ``bool``, determine's whether domain names are
    relativized to the zone's origin.  The default is ``True``.

    *zone_factory*, the zone factory to use or ``None``.  If ``None``, then
    ``dns.zone.Zone`` will be used.  The value may be any class or callable
    that returns a subclass of ``dns.zone.Zone``.

    *filename*, a ``str`` or ``None``, the filename to emit when
    describing where an error occurred; the default is ``'<string>'``.

    *allow_include*, a ``bool``.  If ``True``, the default, then ``$INCLUDE``
    directives are permitted.  If ``False``, then encoutering a ``$INCLUDE``
    will raise a ``SyntaxError`` exception.

    *check_origin*, a ``bool``.  If ``True``, the default, then sanity
    checks of the origin node will be made by calling the zone's
    ``check_origin()`` method.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

    Raises ``dns.zone.NoNS`` if there is no NS RRset.

    Raises ``KeyError`` if there is no origin node.

    Returns a subclass of ``dns.zone.Zone``.
    """

    # 'text' can also be a file, but we don't publish that fact
    # since it's an implementation detail.  The official file
    # interface is from_file().

    if filename is None:
        filename = '<string>'
    zone = zone_factory(origin, rdclass, relativize=relativize)
    with zone.writer(True) as txn:
        tok = dns.tokenizer.Tokenizer(text, filename, idna_codec=idna_codec)
        reader = dns.zonefile.Reader(tok, rdclass, txn,
                                     allow_include=allow_include)
        try:
            reader.read()
        except dns.zonefile.UnknownOrigin:
            # for backwards compatibility
            raise dns.zone.UnknownOrigin
    # Now that we're done reading, do some basic checking of the zone.
    if check_origin:
        zone.check_origin()
    return zone


def from_file(f, origin=None, rdclass=dns.rdataclass.IN,
              relativize=True, zone_factory=Zone, filename=None,
              allow_include=True, check_origin=True):
    """Read a zone file and build a zone object.

    *f*, a file or ``str``.  If *f* is a string, it is treated
    as the name of a file to open.

    *origin*, a ``dns.name.Name``, a ``str``, or ``None``.  The origin
    of the zone; if not specified, the first ``$ORIGIN`` statement in the
    zone file will determine the origin of the zone.

    *rdclass*, an ``int``, the zone's rdata class; the default is class IN.

    *relativize*, a ``bool``, determine's whether domain names are
    relativized to the zone's origin.  The default is ``True``.

    *zone_factory*, the zone factory to use or ``None``.  If ``None``, then
    ``dns.zone.Zone`` will be used.  The value may be any class or callable
    that returns a subclass of ``dns.zone.Zone``.

    *filename*, a ``str`` or ``None``, the filename to emit when
    describing where an error occurred; the default is ``'<string>'``.

    *allow_include*, a ``bool``.  If ``True``, the default, then ``$INCLUDE``
    directives are permitted.  If ``False``, then encoutering a ``$INCLUDE``
    will raise a ``SyntaxError`` exception.

    *check_origin*, a ``bool``.  If ``True``, the default, then sanity
    checks of the origin node will be made by calling the zone's
    ``check_origin()`` method.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

    Raises ``dns.zone.NoNS`` if there is no NS RRset.

    Raises ``KeyError`` if there is no origin node.

    Returns a subclass of ``dns.zone.Zone``.
    """

    with contextlib.ExitStack() as stack:
        if isinstance(f, str):
            if filename is None:
                filename = f
            f = stack.enter_context(open(f))
        return from_text(f, origin, rdclass, relativize, zone_factory,
                         filename, allow_include, check_origin)


def from_xfr(xfr, zone_factory=Zone, relativize=True, check_origin=True):
    """Convert the output of a zone transfer generator into a zone object.

    *xfr*, a generator of ``dns.message.Message`` objects, typically
    ``dns.query.xfr()``.

    *relativize*, a ``bool``, determine's whether domain names are
    relativized to the zone's origin.  The default is ``True``.
    It is essential that the relativize setting matches the one specified
    to the generator.

    *check_origin*, a ``bool``.  If ``True``, the default, then sanity
    checks of the origin node will be made by calling the zone's
    ``check_origin()`` method.

    Raises ``dns.zone.NoSOA`` if there is no SOA RRset.

    Raises ``dns.zone.NoNS`` if there is no NS RRset.

    Raises ``KeyError`` if there is no origin node.

    Returns a subclass of ``dns.zone.Zone``.
    """

    z = None
    for r in xfr:
        if z is None:
            if relativize:
                origin = r.origin
            else:
                origin = r.answer[0].name
            rdclass = r.answer[0].rdclass
            z = zone_factory(origin, rdclass, relativize=relativize)
        for rrset in r.answer:
            znode = z.nodes.get(rrset.name)
            if not znode:
                znode = z.node_factory()
                z.nodes[rrset.name] = znode
            zrds = znode.find_rdataset(rrset.rdclass, rrset.rdtype,
                                       rrset.covers, True)
            zrds.update_ttl(rrset.ttl)
            for rd in rrset:
                zrds.add(rd)
    if check_origin:
        z.check_origin()
    return z
