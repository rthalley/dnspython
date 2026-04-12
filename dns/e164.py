# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2006-2017 Nominum, Inc.
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

"""DNS E.164 helpers."""

from collections.abc import Iterable

import dns.exception
import dns.name
import dns.resolver

#: The public E.164 domain.
public_enum_domain = dns.name.from_text("e164.arpa.")


def from_e164(
    text: str, origin: dns.name.Name | None = public_enum_domain
) -> dns.name.Name:
    """Convert an E.164 number in textual form into a Name object whose
    value is the ENUM domain name for that number.

    Non-digits in the text are ignored, i.e. "16505551212",
    "+1.650.555.1212" and "1 (650) 555-1212" are all the same.

    :param text: An E.164 number in textual form.
    :type text: str
    :param origin: The domain in which the number should be constructed.
        Default is ``e164.arpa.``
    :type origin: :py:class:`dns.name.Name`
    :rtype: :py:class:`dns.name.Name`
    """

    parts = [d for d in text if d.isdigit()]
    parts.reverse()
    return dns.name.from_text(".".join(parts), origin=origin)


def to_e164(
    name: dns.name.Name,
    origin: dns.name.Name | None = public_enum_domain,
    want_plus_prefix: bool = True,
) -> str:
    """Convert an ENUM domain name into an E.164 number.

    Note that dnspython does not have any information about preferred
    number formats within national numbering plans, so all numbers are
    emitted as a simple string of digits, prefixed by a '+' (unless
    *want_plus_prefix* is ``False``).

    :param name: The ENUM domain name.
    :type name: :py:class:`dns.name.Name`
    :param origin: A domain containing the ENUM domain name.  The name is
        relativized to this domain before conversion.  If ``None``, no
        relativization is done.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :param want_plus_prefix: If ``True``, add a ``'+'`` prefix to the
        returned number.
    :type want_plus_prefix: bool
    :rtype: str
    """
    if origin is not None:
        name = name.relativize(origin)
    dlabels = [d for d in name.labels if d.isdigit() and len(d) == 1]
    if len(dlabels) != len(name.labels):
        raise dns.exception.SyntaxError("non-digit labels in ENUM domain name")
    dlabels.reverse()
    text = b"".join(dlabels)
    if want_plus_prefix:
        text = b"+" + text
    return text.decode()


def query(
    number: str,
    domains: Iterable[dns.name.Name | str],
    resolver: dns.resolver.Resolver | None = None,
) -> dns.resolver.Answer:
    """Look for NAPTR RRs for the specified number in the specified domains.

    e.g. lookup('16505551212', ['e164.dnspython.org.', 'e164.arpa.'])

    :param number: The E.164 number to look up.
    :type number: str
    :param domains: An iterable of domain names to search.
    :param resolver: The resolver to use.  If ``None``, the default resolver
        is used.
    :type resolver: :py:class:`dns.resolver.Resolver` or ``None``
    """

    if resolver is None:
        resolver = dns.resolver.get_default_resolver()
    e_nx = dns.resolver.NXDOMAIN()
    for domain in domains:
        if isinstance(domain, str):
            domain = dns.name.from_text(domain)
        qname = from_e164(number, domain)
        try:
            return resolver.resolve(qname, "NAPTR")
        except dns.resolver.NXDOMAIN as e:
            e_nx += e
    raise e_nx
