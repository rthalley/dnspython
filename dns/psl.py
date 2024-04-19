#  Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license.

"""Public Suffix List Support"""

import os.path
import re
from typing import Optional, Set

import dns.name
import dns.namedict

_have_httpx = dns._features.have("doh")
if _have_httpx:
    import httpx

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


class _Node:
    """If the most-enclosing match is a _Node, then there is no public suffix."""

    def __init__(self, name: dns.name.Name):
        self.name = name

    def public_suffix_depth(self, name: dns.name.Name) -> Optional[int]:
        return None


class _ExactNode(_Node):
    """If the most-enclosing match is an _ExactNode, then the public suffix is
    at the depth of the _ExactNode, i.e. is equal to the node's name."""

    def public_suffix_depth(self, name: dns.name.Name) -> Optional[int]:
        return len(self.name)


class _WildNode(_Node):
    """If the most-enclosing match is a _WildNode, then the public suffix is
    at the depth of the _WildNode plus one, or ``None`` if the queried name
    is not deeper than the _WildNode name."""

    def public_suffix_depth(self, name: dns.name.Name) -> Optional[int]:
        if len(name) <= len(self.name):
            return None
        return len(self.name) + 1


class _ExceptionNode(_Node):
    """If the most-enclosing match is an _ExceptionNode, then the public suffix is
    the parent name.  _ExceptionNodes only make sense when their parent is a
    _WildNode."""

    def public_suffix_depth(self, name: dns.name.Name) -> Optional[int]:
        return len(self.name) - 1


class PublicSuffixList:
    """Public suffix list database.

    A *public suffix* or *effective top-level domain* (*eTLD*) is a domain under which a
    user can register names.

    The *base domain*, also known as the *registerable domain* or the *eTLD + 1* is one
    level deeper than the public suffix.  For example, for `www.dnspython.org` the
    public suffix is `org` and the base domain is `dnspython.org`.  Names which are
    public suffixes do not have a base domain.

    The *reduced domain* of a name is the base domain of that name if it is defined, or
    the name itself otherwise.  Reduced domains are useful for statistical aggregations
    where you are principally trying to aggregate by base domain but don't want to lose
    track of queries without base names (e.g. queries to com, or the root).
    """

    def __init__(
        self,
        filename: str,
        categories: Optional[Set[str]] = None,
        allow_unlisted_gtlds: bool = True,
        download_if_needed: bool = False,
        url: str = PSL_URL,
    ):
        """Initialize a public suffix list.

        *filename*, a ``str``, is the filename of the public suffix list, in the
        `standard format <https://github.com/publicsuffix/list/wiki/Format>`. If the
        file does not exist and *download_if_needed* has been specified, then the file
        will be downloaded from the specified *url*.

        *categories*, a set of ``str`` or ``None``, the PSL categories to include when
        searching.  If ``None``, the default set ``{"ICANN", "PRIVATE"}`` is used.  The
        ``"ICANN"`` category is the public suffixes administered by global and national
        registries, and the "PRIVATE" category is public suffixes administred by private
        entities as part of their namespace.

        *allow_unlisted_gtlds*, a ``bool``, with a default of ``True``.  If ``True``,
        then the root node is a wildcard node, and gTLDs not listed in the
        public suffix database will still be considered as public suffixes.  For
        example, a query of "www.example.bogus-gtld." would have a public suffix
        of "bogus-gtld." and a base domain of "example.bogus-gtld.".  If ``False``,
        then ``None`` will be returned for gTLDs which are not listed.

        *download_if_needed*: a ``bool``, defaulting to ``True``.  If ``True``, then
        download the list from the *url* if *filename* does not exist.  If ``False``,
        then *filename* must exist.

        *url*: a ``str``.  The URL to use if downloading the public suffix list is
        required; the default is the standard URL recommended by publicsuffix.org.
        """

        if download_if_needed:
            if not _have_httpx:
                raise ValueError(
                    "download_if_needed is True but httpx is not available"
                )
            if not os.path.isfile(filename):
                response = httpx.request("GET", url)
                if response.status_code == 200:
                    with open(filename, "w") as f:
                        f.write(response.text)
        self.suffixes = dns.namedict.NameDict()
        if allow_unlisted_gtlds:
            root_node: _Node = _WildNode(dns.name.root)
        else:
            root_node = _Node(dns.name.root)
        self.suffixes[dns.name.root] = root_node
        if categories is None:
            categories = {"ICANN", "PRIVATE"}
        assert categories is not None  # for mypy
        pattern = re.compile("// ===(BEGIN|END) ([A-Z]+) DOMAINS===")
        skipping = True
        with open(filename, "r") as f:
            self.mtime = os.fstat(f.fileno()).st_mtime
            for l in f.readlines():
                l = l.rstrip()
                if l.startswith("//"):
                    match = pattern.match(l)
                    if match:
                        op = match.group(1)
                        category = match.group(2)
                        skipping = not (category in categories and op == "BEGIN")
                    continue
                if l == "" or skipping:
                    continue
                if l.startswith("!"):
                    exception = True
                    l = l[1:]
                else:
                    exception = False
                n = dns.name.from_text(l)
                if n.is_wild():
                    n = n.parent()  # remove leading "*" label
                    node: _Node = _WildNode(n)
                elif exception:
                    node = _ExceptionNode(n)
                else:
                    node = _ExactNode(n)
                if self.suffixes.has_key(n):
                    raise ValueError(f"redefinition of {n}")
                self.suffixes[n] = node

    def public_suffix(self, name: dns.name.Name) -> Optional[dns.name.Name]:
        """Return the public suffix for *name*, or ``None`` if it is not defined.

        *name*, a ``dna.name.Name``
        """
        _, node = self.suffixes.get_deepest_match(name)
        depth = node.public_suffix_depth(name)
        if depth is None or depth > len(name):
            return None
        _, suffix = name.split(depth)
        return suffix

    def base_domain(self, name: dns.name.Name) -> Optional[dns.name.Name]:
        """Return the base domain for *name*, or ``None`` if it is not defined.

        *name*, a ``dna.name.Name``
        """
        _, node = self.suffixes.get_deepest_match(name)
        depth = node.public_suffix_depth(name)
        if depth is None or depth >= len(name):
            return None
        _, suffix = name.split(depth + 1)
        return suffix

    def reduced_domain(self, name: dns.name.Name) -> dns.name.Name:
        """Return the reduced domain for *name*.

        *name*, a ``dna.name.Name``
        """
        reduced_name = self.base_domain(name)
        if reduced_name is not None:
            return reduced_name
        else:
            return name
