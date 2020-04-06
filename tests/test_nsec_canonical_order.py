import unittest

from random import randint
import dns.name
import dns.dnssec


class NSECCanonicalOrder(unittest.TestCase):
    # Source: https://tools.ietf.org/html/rfc4034#section-6.1
    DATA = (
        dns.name.from_text(b"example"),
        dns.name.from_text(b"a.example"),
        dns.name.from_text(b"yljkjljk.a.example"),
        dns.name.from_text(b"Z.a.example"),
        dns.name.from_text(b"zABC.a.EXAMPLE"),
        dns.name.from_text(b"z.example"),
        dns.name.from_text(b"\001.z.example"),
        dns.name.from_text(b"*.z.example"),
        dns.name.from_text(b"\200.z.example"),
    )

    TEST_ORDER = [
        (0, 1, -1),
        (5, 6, -1),
        (4, 5, -1),
        (1, 1, 0),
        (8, 8, 0),
        (5, 4, 1),
        (8, 3, 1),
        (7, 6, 1),
    ]

    def test_order_function(self):
        for test_order in self.TEST_ORDER:
            order = dns.dnssec.compare_canonical_order(
                self.DATA[test_order[0]], self.DATA[test_order[1]]
            )
            self.assertEqual(test_order[2], order, test_order)

    def test_order_function_random(self):
        for _ in range(1000):
            i = randint(0, len(self.DATA) - 1)
            j = randint(0, len(self.DATA) - 1)

            result = (i > j) - (i < j)
            order = dns.dnssec.compare_canonical_order(self.DATA[i], self.DATA[j])
            self.assertEqual(result, order, f"{i}, {j}")
