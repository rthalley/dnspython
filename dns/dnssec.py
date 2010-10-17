# Copyright (C) 2003-2007, 2009 Nominum, Inc.
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

"""Common DNSSEC-related functions and constants."""

import dns.name
import dns.rdata
import dns.rdatatype
import dns.rdataclass

RSAMD5 = 1
DH = 2
DSA = 3
ECC = 4
RSASHA1 = 5
DSANSEC3SHA1 = 6
RSASHA1NSEC3SHA1 = 7
RSASHA256 = 8
RSASHA512 = 10
INDIRECT = 252
PRIVATEDNS = 253
PRIVATEOID = 254

_algorithm_by_text = {
    'RSAMD5' : RSAMD5,
    'DH' : DH,
    'DSA' : DSA,
    'ECC' : ECC,
    'RSASHA1' : RSASHA1,
    'DSANSEC3SHA1' : DSANSEC3SHA1,
    'RSASHA1NSEC3SHA1' : RSASHA1NSEC3SHA1,
    'RSASHA256' : RSASHA256,
    'RSASHA512' : RSASHA512,
    'INDIRECT' : INDIRECT,
    'PRIVATEDNS' : PRIVATEDNS,
    'PRIVATEOID' : PRIVATEOID,
    }

# We construct the inverse mapping programmatically to ensure that we
# cannot make any mistakes (e.g. omissions, cut-and-paste errors) that
# would cause the mapping not to be true inverse.

_algorithm_by_value = dict([(y, x) for x, y in _algorithm_by_text.iteritems()])

class UnknownAlgorithm(Exception):
    """Raised if an algorithm is unknown."""
    pass

def algorithm_from_text(text):
    """Convert text into a DNSSEC algorithm value
    @rtype: int"""

    value = _algorithm_by_text.get(text.upper())
    if value is None:
        value = int(text)
    return value

def algorithm_to_text(value):
    """Convert a DNSSEC algorithm value to text
    @rtype: string"""

    text = _algorithm_by_value.get(value)
    if text is None:
        text = str(value)
    return text

def _to_rdata(record):
   s = cStringIO.StringIO()
   record.to_wire(s)
   return s.getvalue()

def key_id(key):
   rdata = _to_rdata(key)
   if key.algorithm == RSAMD5:
       return (ord(rdata[-3]) << 8) + ord(rdata[-2])
   else:
       total = 0
       for i in range(len(rdata) / 2):
           total += (ord(rdata[2 * i]) << 8) + ord(rdata[2 * i + 1])
       if len(rdata) % 2 != 0:
           total += ord(rdata[len(rdata) - 1]) << 8
       total += ((total >> 16) & 0xffff);
       return total & 0xffff

def make_ds(name, key, algorithm):
   if algorithm.upper() == 'SHA1':
       dsalg = 1
       hash = hashlib.sha1()
   elif algorithm.upper() == 'SHA256':
       dsalg = 2
       hash = hashlib.sha256()
   else:
       raise ValueError, 'unsupported algorithm "%s"' % algorithm

   if isinstance(name, str):
       name = dns.name.from_text(name)
   hash.update(name.canonicalize().to_wire())
   hash.update(_to_rdata(key))
   digest = hash.digest()

   dsrdata = struct.pack("!HBB", key_id(key), key.algorithm, dsalg) + digest
   return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DS, dsrdata, 0,
                              len(dsrdata))
