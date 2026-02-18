# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2001-2017 Nominum, Inc.
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

"""DNS rdatasets (an rdataset is a set of rdatas of a given type and class)"""
import dataclasses
import io
import random
import struct
from collections.abc import Collection
from typing import Any, cast

import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.set
import dns.ttl
from dns._render_util import prefixed_length

# define SimpleSet here for backwards compatibility
SimpleSet = dns.set.Set


class DifferingCovers(dns.exception.DNSException):
    """An attempt was made to add a DNS SIG/RRSIG whose covered type
    is not the same as that of the other rdatas in the rdataset."""


class IncompatibleTypes(dns.exception.DNSException):
    """An attempt was made to add DNS RR data of an incompatible type."""


@dataclasses.dataclass(frozen=True)
class RdatasetStyle(dns.rdata.RdataStyle):
    """Rdataset text styles

    An ``RdatasetStyle`` is also a :py:class:`dns.name.NameStyle` and a
    :py:class:`dns.rdata.RdataStyle`.  See those classes
    for a description of their options.

    *override_rdclass*, a ``dns.rdataclass.RdataClass`` or ``None``.
    If not ``None``, use this class instead of the Rdataset's class.

    *want_comments*, a ``bool``.  If ``True``, emit comments for rdata
    which have them.  The default is ``False``.

    *omit_rdclass*, a ``bool``.  If ``True``, do not print the RdataClass.
    The default is ``False``.

    *omit_ttl*, a ``bool``.  If ``True``, do not print the TTL.
    The default is ``False``.  Use of this option may lose information.

    *want_generic*, a ``bool``.  If ``True``, print RdataClass, RdataType,
    and Rdatas in the generic format, a.k.a. the "unknown rdata format".
    The default is ``False``.

    *deduplicate_names*, a ``bool``.  If ``True``, print whitespace instead of the
    owner name if the owner name of an RR is the same as the prior RR's owner name.
    The default is ``False``.

    *first_name_is_duplicate*, a ``bool``.  If ``True``, consider the first owner name
    of the rdataset as a duplicate too, and emit whitespace for it as well.  A sample
    use is in emitting a Node of multiple rdatasets and the current rdataset is not
    the first to be emitted.  The default is ``False``.

    *default_ttl*, an ``int`` or ``None``.  If ``None``, the default, there is no
    default TTL.  If an integer is specified, then any TTL matching that value will
    be omitted.  When emitting a zonefile, a setting other than ``None`` will cause
    a ``$TTL`` directive to be emitted.

    *name_just*, an ``int``.  The owner name field justification.  Negative values
    are left justified, and positive values are right justified.  A value of zero,
    the default, means that no justification is performed.

    *ttl_just*, an ``int``.  The TTL field justification.  Negative values
    are left justified, and positive values are right justified.  A value of zero,
    the default, means that no justification is performed.

    *rdclass_just*, an ``int``.  The RdataClass name field justification.  Negative values
    are left justified, and positive values are right justified.  A value of zero,
    the default, means that no justification is performed.

    *rdtype_just*, an ``int``.  The RdataType field justification.  Negative values
    are left justified, and positive values are right justified.  A value of zero,
    the default, means that no justification is performed.
    """

    override_rdclass: dns.rdataclass.RdataClass | None = None
    want_comments: bool = False
    omit_rdclass: bool = False
    omit_ttl: bool = False
    want_generic: bool = False
    deduplicate_names: bool = False
    first_name_is_duplicate: bool = False
    default_ttl: int | None = None
    name_just: int = 0
    ttl_just: int = 0
    rdclass_just: int = 0
    rdtype_just: int = 0


def justify(text: str, amount: int):
    if amount == 0:
        return text
    if amount < 0:
        return text.ljust(-1 * amount)
    else:
        return text.rjust(amount)


class Rdataset(dns.set.Set):
    """A DNS rdataset."""

    __slots__ = ["rdclass", "rdtype", "covers", "ttl"]

    def __init__(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        covers: dns.rdatatype.RdataType = dns.rdatatype.NONE,
        ttl: int = 0,
    ):
        """Create a new rdataset of the specified class and type.

        *rdclass*, a ``dns.rdataclass.RdataClass``, the rdataclass.

        *rdtype*, an ``dns.rdatatype.RdataType``, the rdatatype.

        *covers*, an ``dns.rdatatype.RdataType``, the covered rdatatype.

        *ttl*, an ``int``, the TTL.
        """

        super().__init__()
        self.rdclass = rdclass
        self.rdtype: dns.rdatatype.RdataType = rdtype
        self.covers: dns.rdatatype.RdataType = covers
        self.ttl = ttl

    def _clone(self):
        obj = cast(Rdataset, super()._clone())
        obj.rdclass = self.rdclass
        obj.rdtype = self.rdtype
        obj.covers = self.covers
        obj.ttl = self.ttl
        return obj

    def update_ttl(self, ttl: int) -> None:
        """Perform TTL minimization.

        Set the TTL of the rdataset to be the lesser of the set's current
        TTL or the specified TTL.  If the set contains no rdatas, set the TTL
        to the specified TTL.

        *ttl*, an ``int`` or ``str``.
        """
        ttl = dns.ttl.make(ttl)
        if len(self) == 0:
            self.ttl = ttl
        elif ttl < self.ttl:
            self.ttl = ttl

    # pylint: disable=arguments-differ,arguments-renamed
    def add(self, rd: dns.rdata.Rdata, ttl: int | None = None) -> None:  # type: ignore
        """Add the specified rdata to the rdataset.

        If the optional *ttl* parameter is supplied, then
        ``self.update_ttl(ttl)`` will be called prior to adding the rdata.

        *rd*, a ``dns.rdata.Rdata``, the rdata

        *ttl*, an ``int``, the TTL.

        Raises ``dns.rdataset.IncompatibleTypes`` if the type and class
        do not match the type and class of the rdataset.

        Raises ``dns.rdataset.DifferingCovers`` if the type is a signature
        type and the covered type does not match that of the rdataset.
        """

        #
        # If we're adding a signature, do some special handling to
        # check that the signature covers the same type as the
        # other rdatas in this rdataset.  If this is the first rdata
        # in the set, initialize the covers field.
        #
        if self.rdclass != rd.rdclass or self.rdtype != rd.rdtype:
            raise IncompatibleTypes
        if ttl is not None:
            self.update_ttl(ttl)
        if self.rdtype == dns.rdatatype.RRSIG or self.rdtype == dns.rdatatype.SIG:
            covers = rd.covers()
            if len(self) == 0 and self.covers == dns.rdatatype.NONE:
                self.covers = covers
            elif self.covers != covers:
                raise DifferingCovers
        if dns.rdatatype.is_singleton(rd.rdtype) and len(self) > 0:
            self.clear()
        super().add(rd)

    def union_update(self, other):
        self.update_ttl(other.ttl)
        super().union_update(other)

    def intersection_update(self, other):
        self.update_ttl(other.ttl)
        super().intersection_update(other)

    def update(self, other):
        """Add all rdatas in other to self.

        *other*, a ``dns.rdataset.Rdataset``, the rdataset from which
        to update.
        """

        self.update_ttl(other.ttl)
        super().update(other)

    def _rdata_repr(self):
        def maybe_truncate(s):
            if len(s) > 100:
                return s[:100] + "..."
            return s

        return "[" + ", ".join(f"<{maybe_truncate(str(rr))}>" for rr in self) + "]"

    def __repr__(self):
        if self.covers == 0:
            ctext = ""
        else:
            ctext = "(" + dns.rdatatype.to_text(self.covers) + ")"
        return (
            "<DNS "
            + dns.rdataclass.to_text(self.rdclass)
            + " "
            + dns.rdatatype.to_text(self.rdtype)
            + ctext
            + " rdataset: "
            + self._rdata_repr()
            + ">"
        )

    def __str__(self):
        return self.to_text()

    def __eq__(self, other):
        if not isinstance(other, Rdataset):
            return False
        if (
            self.rdclass != other.rdclass
            or self.rdtype != other.rdtype
            or self.covers != other.covers
        ):
            return False
        return super().__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_text(
        self,
        name: dns.name.Name | None = None,
        origin: dns.name.Name | None = None,
        relativize: bool = True,
        override_rdclass: dns.rdataclass.RdataClass | None = None,
        want_comments: bool = False,
        style: RdatasetStyle | None = None,
        **kw: Any,
    ) -> str:
        """Convert the rdataset into DNS zone file format.

        See ``dns.name.Name.choose_relativity`` for more information
        on how *origin* and *relativize* determine the way names
        are emitted.

        Any additional keyword arguments are passed on to the rdata
        ``to_text()`` method.

        *name*, a ``dns.name.Name``.  If name is not ``None``, emit RRs with
        *name* as the owner name.

        *origin*, a ``dns.name.Name`` or ``None``, the origin for relative
        names.

        *relativize*, a ``bool``.  If ``True``, names will be relativized
        to *origin*.

        *override_rdclass*, a ``dns.rdataclass.RdataClass`` or ``None``.
        If not ``None``, when rendering, emit records as if they were of this class.

        *want_comments*, a ``bool``.  If ``True``, emit comments for rdata
        which have them.  The default is ``False``.

        *style*, a :py:class:`dns.rdataset.RdatasetStyle` or ``None`` (the default).  If
        specified, the style overrides the other parameters except for *name*.
        """
        if style is None:
            kw = kw.copy()
            kw["origin"] = origin
            kw["relativize"] = relativize
            kw["override_rdclass"] = override_rdclass
            kw["want_comments"] = want_comments
            style = RdatasetStyle.from_keywords(kw)
        return self.to_styled_text(style, name)

    def to_styled_text(
        self, style: RdatasetStyle, name: dns.name.Name | None = None
    ) -> str:
        """Convert the rdataset into styled text format.

        See the documentation for :py:class:`dns.rdataset.RdatasetStyle` for a description
        of the style parameters.
        """
        if name is not None:
            if style.deduplicate_names and style.first_name_is_duplicate:
                ntext = "    "
            else:
                ntext = f"{name.to_styled_text(style)} "
            ntext = justify(ntext, style.name_just)
        else:
            ntext = ""
        s = io.StringIO()
        if style.override_rdclass is not None:
            rdclass = style.override_rdclass
        else:
            rdclass = self.rdclass
        if style.omit_rdclass:
            rdclass_text = ""
        elif style.want_generic:
            rdclass_text = f"CLASS{rdclass} "
        else:
            rdclass_text = f"{dns.rdataclass.to_text(rdclass)} "
        rdclass_text = justify(rdclass_text, style.rdclass_just)
        if style.want_generic:
            rdtype_text = f"TYPE{self.rdtype}"
        else:
            rdtype_text = f"{dns.rdatatype.to_text(self.rdtype)}"
        rdtype_text = justify(rdtype_text, style.rdtype_just)
        if len(self) == 0:
            #
            # Empty rdatasets are used for the question section, and in
            # some dynamic updates, so we don't need to print out the TTL
            # (which is meaningless anyway).
            #
            s.write(f"{ntext}{rdclass_text}{rdtype_text}\n")
        else:
            if style.omit_ttl or (
                style.default_ttl is not None and self.ttl == style.default_ttl
            ):
                ttl = ""
            else:
                ttl = f"{self.ttl} "
            ttl = justify(ttl, style.ttl_just)
            for rd in self:
                extra = ""
                if style.want_comments:
                    if rd.rdcomment:
                        extra = f" ;{rd.rdcomment}"
                if style.want_generic:
                    rdata_text = rd.to_generic().to_styled_text(style)
                else:
                    rdata_text = rd.to_styled_text(style)
                s.write(
                    f"{ntext}{ttl}{rdclass_text}{rdtype_text} {rdata_text}{extra}\n"
                )
                if style.deduplicate_names:
                    ntext = "    "
                    ntext = justify(ntext, style.name_just)

        #
        # We strip off the final \n for the caller's convenience in printing
        #
        return s.getvalue()[:-1]

    def to_wire(
        self,
        name: dns.name.Name,
        file: Any,
        compress: dns.name.CompressType | None = None,
        origin: dns.name.Name | None = None,
        override_rdclass: dns.rdataclass.RdataClass | None = None,
        want_shuffle: bool = True,
    ) -> int:
        """Convert the rdataset to wire format.

        *name*, a ``dns.name.Name`` is the owner name to use.

        *file* is the file where the name is emitted (typically a
        BytesIO file).

        *compress*, a ``dict``, is the compression table to use.  If
        ``None`` (the default), names will not be compressed.

        *origin* is a ``dns.name.Name`` or ``None``.  If the name is
        relative and origin is not ``None``, then *origin* will be appended
        to it.

        *override_rdclass*, an ``int``, is used as the class instead of the
        class of the rdataset.  This is useful when rendering rdatasets
        associated with dynamic updates.

        *want_shuffle*, a ``bool``.  If ``True``, then the order of the
        Rdatas within the Rdataset will be shuffled before rendering.

        Returns an ``int``, the number of records emitted.
        """

        if override_rdclass is not None:
            rdclass = override_rdclass
            want_shuffle = False
        else:
            rdclass = self.rdclass
        if len(self) == 0:
            name.to_wire(file, compress, origin)
            file.write(struct.pack("!HHIH", self.rdtype, rdclass, 0, 0))
            return 1
        else:
            l: Rdataset | list[dns.rdata.Rdata]
            if want_shuffle:
                l = list(self)
                random.shuffle(l)
            else:
                l = self
            for rd in l:
                name.to_wire(file, compress, origin)
                file.write(struct.pack("!HHI", self.rdtype, rdclass, self.ttl))
                with prefixed_length(file, 2):
                    rd.to_wire(file, compress, origin)
            return len(self)

    def match(
        self,
        rdclass: dns.rdataclass.RdataClass,
        rdtype: dns.rdatatype.RdataType,
        covers: dns.rdatatype.RdataType,
    ) -> bool:
        """Returns ``True`` if this rdataset matches the specified class,
        type, and covers.
        """
        if self.rdclass == rdclass and self.rdtype == rdtype and self.covers == covers:
            return True
        return False

    def processing_order(self) -> list[dns.rdata.Rdata]:
        """Return rdatas in a valid processing order according to the type's
        specification.  For example, MX records are in preference order from
        lowest to highest preferences, with items of the same preference
        shuffled.

        For types that do not define a processing order, the rdatas are
        simply shuffled.
        """
        if len(self) == 0:
            return []
        else:
            return self[0]._processing_order(iter(self))  # pyright: ignore


@dns.immutable.immutable
class ImmutableRdataset(Rdataset):  # lgtm[py/missing-equals]
    """An immutable DNS rdataset."""

    _clone_class = Rdataset

    def __init__(self, rdataset: Rdataset):
        """Create an immutable rdataset from the specified rdataset."""

        super().__init__(
            rdataset.rdclass, rdataset.rdtype, rdataset.covers, rdataset.ttl
        )
        self.items = dns.immutable.Dict(rdataset.items)

    def update_ttl(self, ttl):
        raise TypeError("immutable")

    def add(self, rd, ttl=None):  # pyright: ignore
        raise TypeError("immutable")

    def union_update(self, other):
        raise TypeError("immutable")

    def intersection_update(self, other):
        raise TypeError("immutable")

    def update(self, other):
        raise TypeError("immutable")

    def __delitem__(self, i):
        raise TypeError("immutable")

    # lgtm complains about these not raising ArithmeticError, but there is
    # precedent for overrides of these methods in other classes to raise
    # TypeError, and it seems like the better exception.

    def __ior__(self, other):  # lgtm[py/unexpected-raise-in-special-method]
        raise TypeError("immutable")

    def __iand__(self, other):  # lgtm[py/unexpected-raise-in-special-method]
        raise TypeError("immutable")

    def __iadd__(self, other):  # lgtm[py/unexpected-raise-in-special-method]
        raise TypeError("immutable")

    def __isub__(self, other):  # lgtm[py/unexpected-raise-in-special-method]
        raise TypeError("immutable")

    def clear(self):
        raise TypeError("immutable")

    def __copy__(self):
        return ImmutableRdataset(super().copy())  # pyright: ignore

    def copy(self):
        return ImmutableRdataset(super().copy())  # pyright: ignore

    def union(self, other):
        return ImmutableRdataset(super().union(other))  # pyright: ignore

    def intersection(self, other):
        return ImmutableRdataset(super().intersection(other))  # pyright: ignore

    def difference(self, other):
        return ImmutableRdataset(super().difference(other))  # pyright: ignore

    def symmetric_difference(self, other):
        return ImmutableRdataset(super().symmetric_difference(other))  # pyright: ignore


def from_text_list(
    rdclass: dns.rdataclass.RdataClass | str,
    rdtype: dns.rdatatype.RdataType | str,
    ttl: int,
    text_rdatas: Collection[str],
    idna_codec: dns.name.IDNACodec | None = None,
    origin: dns.name.Name | None = None,
    relativize: bool = True,
    relativize_to: dns.name.Name | None = None,
) -> Rdataset:
    """Create an rdataset with the specified class, type, and TTL, and with
    the specified list of rdatas in text format.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder to use; if ``None``, the default IDNA 2003
    encoder/decoder is used.

    *origin*, a ``dns.name.Name`` (or ``None``), the
    origin to use for relative names.

    *relativize*, a ``bool``.  If true, name will be relativized.

    *relativize_to*, a ``dns.name.Name`` (or ``None``), the origin to use
    when relativizing names.  If not set, the *origin* value will be used.

    Returns a ``dns.rdataset.Rdataset`` object.
    """

    rdclass = dns.rdataclass.RdataClass.make(rdclass)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    r = Rdataset(rdclass, rdtype)
    r.update_ttl(ttl)
    for t in text_rdatas:
        rd = dns.rdata.from_text(
            r.rdclass, r.rdtype, t, origin, relativize, relativize_to, idna_codec
        )
        r.add(rd)
    return r


def from_text(
    rdclass: dns.rdataclass.RdataClass | str,
    rdtype: dns.rdatatype.RdataType | str,
    ttl: int,
    *text_rdatas: Any,
) -> Rdataset:
    """Create an rdataset with the specified class, type, and TTL, and with
    the specified rdatas in text format.

    Returns a ``dns.rdataset.Rdataset`` object.
    """

    return from_text_list(rdclass, rdtype, ttl, cast(Collection[str], text_rdatas))


def from_rdata_list(ttl: int, rdatas: Collection[dns.rdata.Rdata]) -> Rdataset:
    """Create an rdataset with the specified TTL, and with
    the specified list of rdata objects.

    Returns a ``dns.rdataset.Rdataset`` object.
    """

    if len(rdatas) == 0:
        raise ValueError("rdata list must not be empty")
    r = None
    for rd in rdatas:
        if r is None:
            r = Rdataset(rd.rdclass, rd.rdtype)
            r.update_ttl(ttl)
        r.add(rd)
    assert r is not None
    return r


def from_rdata(ttl: int, *rdatas: Any) -> Rdataset:
    """Create an rdataset with the specified TTL, and with
    the specified rdata objects.

    Returns a ``dns.rdataset.Rdataset`` object.
    """

    return from_rdata_list(ttl, cast(Collection[dns.rdata.Rdata], rdatas))
