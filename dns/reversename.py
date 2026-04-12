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

"""DNS Reverse Map Names."""

import binascii

import dns.exception
import dns.ipv4
import dns.ipv6
import dns.name

ipv4_reverse_domain = dns.name.from_text("in-addr.arpa.")
ipv6_reverse_domain = dns.name.from_text("ip6.arpa.")


def from_address(
    text: str,
    v4_origin: dns.name.Name = ipv4_reverse_domain,
    v6_origin: dns.name.Name = ipv6_reverse_domain,
) -> dns.name.Name:
    """Convert an IPv4 or IPv6 address in textual form into a Name object whose
    value is the reverse-map domain name of the address.

    :param text: An IPv4 or IPv6 address in textual form (e.g. ``'127.0.0.1'``,
        ``'::1'``).
    :type text: str
    :param v4_origin: Domain to append for IPv4 addresses instead of
        ``in-addr.arpa.``
    :type v4_origin: :py:class:`dns.name.Name`
    :param v6_origin: Domain to append for IPv6 addresses instead of
        ``ip6.arpa.``
    :type v6_origin: :py:class:`dns.name.Name`
    :raises dns.exception.SyntaxError: If the address is badly formed.
    :rtype: :py:class:`dns.name.Name`
    """

    try:
        v6 = dns.ipv6.inet_aton(text)
        if dns.ipv6.is_mapped(v6):
            parts = [str(byte) for byte in v6[12:]]
            origin = v4_origin
        else:
            parts = [x for x in str(binascii.hexlify(v6).decode())]
            origin = v6_origin
    except Exception:
        parts = [str(byte) for byte in dns.ipv4.inet_aton(text)]
        origin = v4_origin
    return dns.name.from_text(".".join(reversed(parts)), origin=origin)


def to_address(
    name: dns.name.Name,
    v4_origin: dns.name.Name = ipv4_reverse_domain,
    v6_origin: dns.name.Name = ipv6_reverse_domain,
) -> str:
    """Convert a reverse map domain name into textual address form.

    :param name: An IPv4 or IPv6 address in reverse-map name form.
    :type name: :py:class:`dns.name.Name`
    :param v4_origin: Top-level domain for IPv4 addresses (default
        ``in-addr.arpa.``).
    :type v4_origin: :py:class:`dns.name.Name`
    :param v6_origin: Top-level domain for IPv6 addresses (default
        ``ip6.arpa.``).
    :type v6_origin: :py:class:`dns.name.Name`
    :raises dns.exception.SyntaxError: If the name does not have a
        reverse-map form.
    :rtype: str
    """

    if name.is_subdomain(v4_origin):
        name = name.relativize(v4_origin)
        text = b".".join(reversed(name.labels))
        # run through inet_ntoa() to check syntax and make pretty.
        return dns.ipv4.inet_ntoa(dns.ipv4.inet_aton(text))
    elif name.is_subdomain(v6_origin):
        name = name.relativize(v6_origin)
        labels = list(reversed(name.labels))
        parts = []
        for i in range(0, len(labels), 4):
            parts.append(b"".join(labels[i : i + 4]))
        text = b":".join(parts)
        # run through inet_ntoa() to check syntax and make pretty.
        return dns.ipv6.inet_ntoa(dns.ipv6.inet_aton(text))
    else:
        raise dns.exception.SyntaxError("unknown reverse-map address family")
