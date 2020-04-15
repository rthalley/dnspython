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

import struct

from base64 import b64encode, b64decode

import dns.exception
import dns.rdata
import dns.name

"""SVCB-like base class."""

def svc_param_key_to_wire(key):
    keys = {
        "alpn": 1,
        "no-default-alpn": 2,
        "port": 3,
        "ipv4hint": 4,
        "echconfig": 5,
        "ipv6hint": 6,
    }

    if key in keys:
        return keys[key]

    if not key.startswith("key"):
        raise dns.exception.FormError

    return int(key[3:])

def svc_param_key_from_wire(key):
    keys = {
        1: "alpn",
        2: "no-default-alpn",
        3: "port",
        4: "ipv4hint",
        5: "echconfig",
        6: "ipv6hint",
    }

    if key in keys:
        return keys[key]

    return "key%d" % (key)

def svc_param_val_to_text(key, val):
    if key == "alpn":
        return ','.join(val)

    if key == "no-default-alpn":
        return None

    if key == "port":
        return str(val)

    if key == "ipv4hint":
        return ','.join(val)

    if key == "echconfig":
        return b64encode(val).decode('utf-8')

    if key == "ipv6hint":
        return ','.join(val)

    return val

def svc_param_val_from_text(key, val):
    if key == "alpn":
        return val.split(',')

    if key == "no-default-alpn":
        return None

    if key == "port":
        return int(val)

    if key == "ipv4hint":
        return val.split(',')

    if key == "echconfig":
        return b64decode(val)

    if key == "ipv6hint":
        return val.split(',')

    return val

def svc_param_val_to_wire(key, val):
    if key == "alpn":
        alpn_ids_bytes = []

        for alpn_id in val:
            alpn_len_bytes = struct.pack("!B", len(alpn_id))
            alpn_id_bytes = b''.join((alpn_len_bytes, alpn_id.encode()))
            alpn_ids_bytes.append(alpn_id_bytes)

        return b''.join(alpn_ids_bytes)

    if key == "no-default-alpn":
        return None # no value for this key

    if key == "port":
        return struct.pack("!H", val)

    if key == "ipv4hint":
        return b''.join(dns.ipv4.inet_aton(ip) for ip in val)

    if key == "echconfig":
        return val

    if key == "ipv6hint":
        return b''.join(dns.inet.inet_pton(dns.inet.AF_INET6, ip) for ip in val)

    return val.encode()

def svc_param_val_from_wire(key, val):
    if key == "alpn":
        current = 0
        val_len = len(val)

        alpn_ids = []

        while val_len > 0:
            (alpn_len,) = struct.unpack("!B", val[current: current + 1])
            current += 1
            val_len -= 1

            alpn = val[current: current + alpn_len].decode('utf-8')
            current += len(alpn)
            val_len -= len(alpn)

            alpn_ids.append(alpn)

        return alpn_ids

    if key == "no-default-alpn":
        return None # no value for this key

    if key == "port":
        (port,) = struct.unpack("!H", val)
        return port

    if key == "ipv4hint":
        current = 0
        val_len = len(val)

        addrs = []

        while val_len >= 4:
            addr = dns.ipv4.inet_ntoa(val[current: current + 4])
            current += 4
            val_len -= 4

            addrs.append(addr)

        return addrs

    if key == "echconfig":
        return val

    if key == "ipv6hint":
        current = 0
        val_len = len(val)

        addrs = []

        while val_len >= 16:
            addr = dns.inet.inet_ntop(dns.inet.AF_INET6, val[current: current + 16])
            current += 16
            val_len -= 16

            addrs.append(addr)

        return addrs

    return val.decode('utf-8')

class SVCBBase(dns.rdata.Rdata):

    """Base class for rdata that is like an SVCB record

    @ivar priority: the priority
    @type priority: int
    @ivar target: the target host
    @type target: dns.name.Name object
    @ivar fields: fields describing the alternative service endpoint
    @type fields: list of (key, value) tuples
    @see: draft-ietf-dnsop-svcb-https-00
    """

    __slots__ = ['priority', 'target', 'fields']

    def __init__(self, rdclass, rdtype, priority, target, fields=None):
        super().__init__(rdclass, rdtype)
        object.__setattr__(self, 'priority', priority)
        object.__setattr__(self, 'target', target)
        object.__setattr__(self, 'fields', fields)

    def to_text(self, origin=None, relativize=True, **kw):
        target = self.target.choose_relativity(origin, relativize)

        if len(self.fields) == 0:
            return '%d %s' % (self.priority, target)

        fields = []

        for (key, val) in self.fields:
            if val is not None:
                string = '%s=%s' % (key, svc_param_val_to_text(key, val))
            else:
                string = key

            fields.append(string)

        fields = ' '.join(fields)

        return '%d %s %s' % (self.priority, target, fields)

    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True,
                  relativize_to=None):
        priority = tok.get_uint16()
        target = tok.get_name(origin, relativize, relativize_to)

        fields = []

        while True:
            t = tok.get()

            if t.is_eol_or_eof():
                break

            if not t.is_identifier():
                raise dns.exception.SyntaxError('expecting a string')

            key = t.value
            val = None

            if '=' in key:
                (key, val) =  key.split('=', 1)

            fields.append((key, svc_param_val_from_text(key, val)))

        return cls(rdclass, rdtype, priority, target, fields)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        priority = struct.pack("!H", self.priority)
        file.write(priority)

        self.target.to_wire(file, compress, origin)

        for (key, val) in self.fields:
            key_wire = struct.pack("!H", svc_param_key_to_wire(key))
            file.write(key_wire)

            val_len = 0

            if val is not None:
                val = svc_param_val_to_wire(key, val)
                val_len = len(val)

            val_len = struct.pack("!H", val_len)
            file.write(val_len)

            if val is not None:
                file.write(val)

    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        (priority,) = struct.unpack('!H', wire[current: current + 2])
        current += 2
        rdlen -= 2

        (target, cused) = dns.name.from_wire(wire[: current + rdlen],
                                             current)
        current += cused
        rdlen -= cused

        fields = []

        while rdlen >= 4:
            (key, val_len) = struct.unpack('!HH', wire[current: current + 4])
            current += 4
            rdlen -= 4

            if rdlen < val_len:
                raise dns.exception.FormError

            key = svc_param_key_from_wire(key)

            val = None

            if val_len > 0:
                val = wire[current: current + val_len].unwrap()
                current += val_len
                rdlen -= val_len

                val = svc_param_val_from_wire(key, val)

            fields.append((key, val))

        if rdlen != 0:
            raise dns.exception.FormError

        return cls(rdclass, rdtype, priority, target, fields)
