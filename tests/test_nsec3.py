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

import unittest

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.TXT
import dns.ttl


class NSEC3TestCase(unittest.TestCase):
    def test_NSEC3_bitmap(self):
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            "1 0 100 ABCD SCBCQHKU35969L2A68P3AD59LHF30715 A CAA TYPE65534",
        )
        bitmap = bytearray(b"\0" * 32)
        bitmap[31] = bitmap[31] | 2
        self.assertEqual(
            rdata.windows, ((0, b"@"), (1, b"@"), (255, bitmap))  # CAA = 257
        )

    def test_NSEC3_bad_bitmaps(self):
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            "1 0 100 ABCD SCBCQHKU35969L2A68P3AD59LHF30715 A CAA",
        )

        with self.assertRaises(dns.exception.FormError):
            copy = bytearray(rdata.to_wire())
            copy[-3] = 0
            dns.rdata.from_wire("IN", "NSEC3", copy, 0, len(copy))

    def test_NSEC3_bitmap_trailing_zero_octet(self):
        # RFC 4034 Sec 4.1.2: a window's bitmap must not carry trailing zero
        # octets, and a window with no types present must not appear.  The wire
        # parser used to accept both and keep the non-canonical bytes; check
        # that they are now FormErrors.  The prefix here is a valid NSEC3 with a
        # single type ("A") whose bitmap is the last three octets, 00 01 40.
        rdata = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3,
            "1 0 100 ABCD SCBCQHKU35969L2A68P3AD59LHF30715 A",
        )
        prefix = bytes(rdata.to_wire())[:-3]
        # window 0, length 2, bitmap 40 00: a trailing zero octet.
        trailing = prefix + bytes([0, 2, 0x40, 0])
        with self.assertRaises(dns.exception.FormError):
            dns.rdata.from_wire("IN", "NSEC3", trailing, 0, len(trailing))
        # window 0, length 1, bitmap 00: a block with no types present.
        empty = prefix + bytes([0, 1, 0])
        with self.assertRaises(dns.exception.FormError):
            dns.rdata.from_wire("IN", "NSEC3", empty, 0, len(empty))


if __name__ == "__main__":
    unittest.main()
