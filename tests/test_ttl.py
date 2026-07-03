# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

import dns.ttl


class TTLTestCase(unittest.TestCase):
    def test_bind_style_ok(self):
        ttl = dns.ttl.from_text("2w1d1h1m1s")
        self.assertEqual(ttl, 2 * 604800 + 86400 + 3600 + 60 + 1)

    def test_bind_style_ok2(self):
        # no one should do this, but it is legal! :)
        ttl = dns.ttl.from_text("1s2w1m1d1h")
        self.assertEqual(ttl, 2 * 604800 + 86400 + 3600 + 60 + 1)

    def test_bind_style_bad_unit(self):
        with self.assertRaises(dns.ttl.BadTTL):
            dns.ttl.from_text("5y")

    def test_bind_style_no_unit(self):
        with self.assertRaises(dns.ttl.BadTTL):
            dns.ttl.from_text("1d5")

    def test_bind_style_leading_unit(self):
        with self.assertRaises(dns.ttl.BadTTL):
            dns.ttl.from_text("s")

    def test_bind_style_unit_without_digits(self):
        with self.assertRaises(dns.ttl.BadTTL):
            dns.ttl.from_text("1mw")

    def test_ttl_technically_too_big_but_tolerated(self):
        ttl = dns.ttl.from_text("4294967295")
        assert ttl == 4294967295

    def test_ttl_technically_too_big(self):
        with self.assertRaises(dns.ttl.BadTTL):
            dns.ttl.from_text("4294967296")

    def test_empty(self):
        with self.assertRaises(dns.ttl.BadTTL):
            dns.ttl.from_text("")

    def test_non_decimal_unicode_digits(self):
        # str.isdigit() is True for Unicode "digit" characters (e.g. the
        # superscript "\u00b2" or the Ethiopic "\u1369") that int() cannot
        # convert, so these must be rejected as a BadTTL rather than leaking a
        # bare ValueError.
        for text in ("\u00b2", "1\u00b2", "\u00b2w", "1\u00b2s", "\u1369"):
            with self.assertRaises(dns.ttl.BadTTL):
                dns.ttl.from_text(text)
