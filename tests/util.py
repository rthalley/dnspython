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

import enum
import inspect
import os
import socket

import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype

# Cache for is_internet_reachable()
_internet_reachable = None
_have_ipv4 = False
_have_ipv6 = False


def here(filename):
    return os.path.join(os.path.dirname(__file__), filename)


def check_networking(addresses):
    """Can we do a DNS resolution via UDP and TCP to at least one of the addresses?"""
    for address in addresses:
        try:
            q = dns.message.make_query(dns.name.root, dns.rdatatype.NS)
            ok = False
            # We try UDP a few times in case we get unlucky and a packet is lost.
            for i in range(5):
                # We don't check the answer other than make sure there is one.
                try:
                    r = dns.query.udp(q, address, timeout=4)
                    ns = r.find_rrset(
                        r.answer, dns.name.root, dns.rdataclass.IN, dns.rdatatype.NS
                    )
                    ok = True
                    break
                except Exception:
                    continue  # UDP try loop
            if not ok:
                continue  # addresses loop
            try:
                r = dns.query.tcp(q, address, timeout=4)
                ns = r.find_rrset(
                    r.answer, dns.name.root, dns.rdataclass.IN, dns.rdatatype.NS
                )
                # UDP and TCP both work!
                return True
            except Exception:
                continue
        except Exception as e:
            pass
    return False


def is_internet_reachable():
    """Check if the Internet is reachable.

    Setting the environment variable `NO_INTERNET` will let this
    function always return False. The result is cached.

    We check using the Google and Cloudflare public resolvers as they are highly
    available and have well-known stable addresses.
    """
    global _internet_reachable
    if _internet_reachable is None:
        if os.environ.get("NO_INTERNET"):
            _internet_reachable = False
        else:
            global _have_ipv4
            _have_ipv4 = check_networking(["8.8.8.8", "1.1.1.1"])
            global _have_ipv6
            _have_ipv6 = check_networking(
                ["2001:4860:4860::8888", "2606:4700:4700::1111"]
            )
            _internet_reachable = _have_ipv4 or _have_ipv6
    return _internet_reachable


def have_ipv4():
    if not is_internet_reachable():
        return False
    return _have_ipv4


def have_ipv6():
    if not is_internet_reachable():
        return False
    return _have_ipv6


def enumerate_module(module, super_class):
    """Yield module attributes which are subclasses of given class"""
    for attr_name in dir(module):
        attr = getattr(module, attr_name)
        if inspect.isclass(attr) and issubclass(attr, super_class):
            yield attr


def check_enum_exports(module, eq_callback, only=None):
    """Make sure module exports all mnemonics from enums"""
    for attr in enumerate_module(module, enum.Enum):
        if only is not None and attr not in only:
            # print('SKIP', attr)
            continue
        for flag, value in attr.__members__.items():
            # print(module, flag, value)
            eq_callback(getattr(module, flag), value)
