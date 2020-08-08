# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

import dns.immutable


class ImmutableTestCase(unittest.TestCase):

    def test_ImmutableDict_hash(self):
        d1 = dns.immutable.ImmutableDict({'a': 1, 'b': 2})
        d2 = dns.immutable.ImmutableDict({'b': 2, 'a': 1})
        d3 = {'b': 2, 'a': 1}
        self.assertEqual(d1, d2)
        self.assertEqual(d2, d3)
        self.assertEqual(hash(d1), hash(d2))

    def test_ImmutableDict_hash_cache(self):
        d = dns.immutable.ImmutableDict({'a': 1, 'b': 2})
        self.assertEqual(d._hash, None)
        h1 = hash(d)
        self.assertEqual(d._hash, h1)
        h2 = hash(d)
        self.assertEqual(h1, h2)

    def test_constify(self):
        items = (
            (bytearray([1, 2, 3]), b'\x01\x02\x03'),
            ((1, 2, 3), (1, 2, 3)),
            ((1, [2], 3), (1, (2,), 3)),
            ([1, 2, 3], (1, 2, 3)),
            ([1, {'a': [1, 2]}],
             (1, dns.immutable.ImmutableDict({'a': (1, 2)}))),
            ('hi', 'hi'),
            (b'hi', b'hi'),
        )
        for input, expected in items:
            self.assertEqual(dns.immutable.constify(input), expected)
        self.assertIsInstance(dns.immutable.constify({'a': 1}),
                              dns.immutable.ImmutableDict)
