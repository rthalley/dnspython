# -*- coding: utf-8
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

import operator
import unittest

from io import BytesIO

import dns.edns

class OptionTestCase(unittest.TestCase):
    def testGenericOption(self):
        opt = dns.edns.GenericOption(3, b'data')
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b'data')
        self.assertEqual(dns.edns.option_from_wire(3, data, 0, len(data)), opt)

    def testECSOption_prefix_length(self):
        opt = dns.edns.ECSOption('1.2.255.33', 20)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b'\x00\x01\x14\x00\x01\x02\xf0')

    def testECSOption(self):
        opt = dns.edns.ECSOption('1.2.3.4', 24)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b'\x00\x01\x18\x00\x01\x02\x03')

    def testECSOption25(self):
        opt = dns.edns.ECSOption('1.2.3.255', 25)
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b'\x00\x01\x19\x00\x01\x02\x03\x80')

        opt2 = dns.edns.option_from_wire(dns.edns.ECS, data, 0, len(data))
        self.assertEqual(opt2.otype, dns.edns.ECS)
        self.assertEqual(opt2.address, '1.2.3.128')
        self.assertEqual(opt2.srclen, 25)
        self.assertEqual(opt2.scopelen, 0)

    def testECSOption_v6(self):
        opt = dns.edns.ECSOption('2001:4b98::1')
        io = BytesIO()
        opt.to_wire(io)
        data = io.getvalue()
        self.assertEqual(data, b'\x00\x02\x38\x00\x20\x01\x4b\x98\x00\x00\x00')

        opt2 = dns.edns.option_from_wire(dns.edns.ECS, data, 0, len(data))
        self.assertEqual(opt2.otype, dns.edns.ECS)
        self.assertEqual(opt2.address, '2001:4b98::')
        self.assertEqual(opt2.srclen, 56)
        self.assertEqual(opt2.scopelen, 0)

    def testECSOption_from_text_valid(self):
        ecs1 = dns.edns.ECSOption.from_text('1.2.3.4/24/0')
        self.assertEqual(ecs1, dns.edns.ECSOption('1.2.3.4', 24, 0))

        ecs2 = dns.edns.ECSOption.from_text('1.2.3.4/24')
        self.assertEqual(ecs2, dns.edns.ECSOption('1.2.3.4', 24, 0))

        ecs3 = dns.edns.ECSOption.from_text('ECS 1.2.3.4/24')
        self.assertEqual(ecs3, dns.edns.ECSOption('1.2.3.4', 24, 0))

        ecs4 = dns.edns.ECSOption.from_text('ECS 1.2.3.4/24/32')
        self.assertEqual(ecs4, dns.edns.ECSOption('1.2.3.4', 24, 32))

        ecs5 = dns.edns.ECSOption.from_text('2001:4b98::1/64/56')
        self.assertEqual(ecs5, dns.edns.ECSOption('2001:4b98::1', 64, 56))

        ecs6 = dns.edns.ECSOption.from_text('2001:4b98::1/64')
        self.assertEqual(ecs6, dns.edns.ECSOption('2001:4b98::1', 64, 0))

        ecs7 = dns.edns.ECSOption.from_text('ECS 2001:4b98::1/0')
        self.assertEqual(ecs7, dns.edns.ECSOption('2001:4b98::1', 0, 0))

        ecs8 = dns.edns.ECSOption.from_text('ECS 2001:4b98::1/64/128')
        self.assertEqual(ecs8, dns.edns.ECSOption('2001:4b98::1', 64, 128))

    def testECSOption_from_text_invalid(self):
        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text('some random text 1.2.3.4/24/0 24')

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text('1.2.3.4/twentyfour')

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text('1.2.3.4/24/O') # <-- that's not a zero

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text('')

        with self.assertRaises(ValueError):
            dns.edns.ECSOption.from_text('1.2.3.4/2001:4b98::1/24')

    def test_basic_relations(self):
        o1 = dns.edns.ECSOption.from_text('1.2.3.0/24/0')
        o2 = dns.edns.ECSOption.from_text('1.2.4.0/24/0')
        self.assertTrue(o1 == o1)
        self.assertTrue(o1 != o2)
        self.assertTrue(o1 < o2)
        self.assertTrue(o1 <= o2)
        self.assertTrue(o2 > o1)
        self.assertTrue(o2 >= o1)
        o1 = dns.edns.ECSOption.from_text('1.2.4.0/23/0')
        o2 = dns.edns.ECSOption.from_text('1.2.4.0/24/0')
        self.assertTrue(o1 < o2)
        o1 = dns.edns.ECSOption.from_text('1.2.4.0/24/0')
        o2 = dns.edns.ECSOption.from_text('1.2.4.0/24/1')
        self.assertTrue(o1 < o2)

    def test_incompatible_relations(self):
        o1 = dns.edns.GenericOption(3, b'data')
        o2 = dns.edns.ECSOption.from_text('1.2.3.5/24/0')
        for oper in [operator.lt, operator.le, operator.ge, operator.gt]:
            self.assertRaises(TypeError, lambda: oper(o1, o2))
        self.assertFalse(o1 == o2)
        self.assertTrue(o1 != o2)
        self.assertFalse(o1 == 123)
        self.assertTrue(o1 != 123)
