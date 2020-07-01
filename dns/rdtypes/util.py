# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2006, 2007, 2009-2011 Nominum, Inc.
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

import dns.exception
import dns.name
import dns.ipv4
import dns.ipv6

class Gateway:
    """A helper class for the IPSECKEY gateway and AMTRELAY relay fields"""
    name = ""

    def __init__(self, type, gateway=None):
        self.type = type
        self.gateway = gateway

    def _invalid_type(self):
        return f"invalid {self.name} type: {self.type}"

    def check(self):
        if self.type == 0:
            if self.gateway not in (".", None):
                raise SyntaxError(f"invalid {self.name} for type 0")
            self.gateway = None
        elif self.type == 1:
            # check that it's OK
            dns.ipv4.inet_aton(self.gateway)
        elif self.type == 2:
            # check that it's OK
            dns.ipv6.inet_aton(self.gateway)
        elif self.type == 3:
            if not isinstance(self.gateway, dns.name.Name):
                raise SyntaxError(f"invalid {self.name}; not a name")
        else:
            raise SyntaxError(self._invalid_type())

    def to_text(self, origin=None, relativize=True):
        if self.type == 0:
            return "."
        elif self.type in (1, 2):
            return self.gateway
        elif self.type == 3:
            return str(self.gateway.choose_relativity(origin, relativize))
        else:
            raise ValueError(self._invalid_type())

    def from_text(self, tok, origin=None, relativize=True, relativize_to=None):
        if self.type in (0, 1, 2):
            return tok.get_string()
        elif self.type == 3:
            return tok.get_name(origin, relativize, relativize_to)
        else:
            raise dns.exception.SyntaxError(self._invalid_type())

    def to_wire(self, file, compress=None, origin=None, canonicalize=False):
        if self.type == 0:
            pass
        elif self.type == 1:
            file.write(dns.ipv4.inet_aton(self.gateway))
        elif self.type == 2:
            file.write(dns.ipv6.inet_aton(self.gateway))
        elif self.type == 3:
            self.gateway.to_wire(file, None, origin, False)
        else:
            raise ValueError(self._invalid_type())

    def from_wire(self, wire, current, rdlen, origin=None):
        if self.type == 0:
            return (None, 0)
        elif self.type == 1:
            return (dns.ipv4.inet_ntoa(wire[current: current + 4]), 4)
        elif self.type == 2:
            return (dns.ipv6.inet_ntoa(wire[current: current + 16]), 16)
        elif self.type == 3:
            return dns.name.from_wire(wire[: current + rdlen], current)
        else:
            raise dns.exception.FormError(self._invalid_type())
