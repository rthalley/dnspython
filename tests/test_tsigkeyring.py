# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import base64
import unittest
import os
import dns.tsig
import dns.tsigkeyring
import pytest

text_keyring = {"keyname.": ("hmac-sha256.", "NjHwPsMKjdN++dOfE5iAiQ==")}

alt_text_keyring = {"keyname.": (dns.tsig.HMAC_SHA256, "NjHwPsMKjdN++dOfE5iAiQ==")}

old_text_keyring = {"keyname.": "NjHwPsMKjdN++dOfE5iAiQ=="}

key = dns.tsig.Key("keyname.", "NjHwPsMKjdN++dOfE5iAiQ==")

rich_keyring = {key.name: key}

old_rich_keyring = {key.name: key.secret}

keyring_file_1 = {
    dns.name.from_text("aaa-test"): dns.tsig.Key(
        dns.name.from_text("aaa-test"),
        "WklIGweRJDBzgYJAfFAt3ln7NJAyz66W56/fpoeepVn5yqs3i3iiXFIS6GXpuFw0TyRfADBcnap8Vvl7TokfYA==",
        "hmac-sha512",
    )
}

keyring_file_2 = {
    dns.name.from_text("b-key"): dns.tsig.Key(
        dns.name.from_text("b-key"),
        "KykTutSQNZYc+o8rqfMPH7ce2a9SruvKgPAqfn8EER8=",
        "hmac-sha256",
    )
}

keyring_file_3 = {
    dns.name.from_text("example.com"): dns.tsig.Key(
        dns.name.from_text("example.com"),
        "WklIGweRJDBzgYJAfFAt3ln7NJAyz66W56/fpoeepVn5yqs3i3iiXFIS6GXpuFw0TyRfADBcnap8Vvl7TokfYA==",
    ).secret
}

keyring_file_4 = {
    dns.name.from_text("bh-"): dns.tsig.Key(
        dns.name.from_text("bh-"),
        "WklIGweRJDBzgYJAfFAt3ln7NJAyz66W56/fpoeepVn5yqs3i3iiXFIS6GXpuFw0TyRfADBcnap8Vvl7TokfYA==",
        "hmac-sha512",
    )
}

TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class TSIGKeyRingTestCase(unittest.TestCase):
    def test_from_text(self):
        """text keyring -> rich keyring"""
        rkeyring = dns.tsigkeyring.from_text(text_keyring)
        self.assertEqual(rkeyring, rich_keyring)

    def test_from_alt_text(self):
        """alternate format text keyring -> rich keyring"""
        rkeyring = dns.tsigkeyring.from_text(alt_text_keyring)
        self.assertEqual(rkeyring, rich_keyring)

    def test_from_old_text(self):
        """old format text keyring -> rich keyring"""
        rkeyring = dns.tsigkeyring.from_text(old_text_keyring)
        self.assertEqual(rkeyring, old_rich_keyring)

    def test_to_text(self):
        """text keyring -> rich keyring -> text keyring"""
        tkeyring = dns.tsigkeyring.to_text(rich_keyring)
        self.assertEqual(tkeyring, text_keyring)

    def test_old_to_text(self):
        """text keyring -> rich keyring -> text keyring"""
        tkeyring = dns.tsigkeyring.to_text(old_rich_keyring)
        self.assertEqual(tkeyring, old_text_keyring)

    def test_from_and_to_text(self):
        """text keyring -> rich keyring -> text keyring"""
        rkeyring = dns.tsigkeyring.from_text(text_keyring)
        tkeyring = dns.tsigkeyring.to_text(rkeyring)
        self.assertEqual(tkeyring, text_keyring)

    def test_old_from_and_to_text(self):
        """text keyring -> rich keyring -> text keyring"""
        rkeyring = dns.tsigkeyring.from_text(old_text_keyring)
        tkeyring = dns.tsigkeyring.to_text(rkeyring)
        self.assertEqual(tkeyring, old_text_keyring)

    def test_from_file_1(self):
        """test to parse key file 1.key"""
        keyring = dns.tsigkeyring.from_file(os.path.join(TEST_DIR, "./tsigkeys/1.key"))
        self.assertEqual(keyring, keyring_file_1)

    def test_from_file_2(self):
        """test to parse key file 2.key"""
        keyring = dns.tsigkeyring.from_file(os.path.join(TEST_DIR, "./tsigkeys/2.key"))
        self.assertEqual(keyring, keyring_file_2)

    def test_from_file_3(self):
        """test to parse key file 3.key"""
        keyring = dns.tsigkeyring.from_file(os.path.join(TEST_DIR, "./tsigkeys/3.key"))
        self.assertEqual(keyring, keyring_file_3)

    def test_from_file_4(self):
        """test to parse key file 4.key"""
        keyring = dns.tsigkeyring.from_file(os.path.join(TEST_DIR, "./tsigkeys/4.key"))
        self.assertEqual(keyring, keyring_file_4)

    def test_from_file_error(self):
        """test to parse key file 5.key"""
        with pytest.raises(Exception):
            keyring = dns.tsigkeyring.from_file(
                os.path.join(TEST_DIR, "./tsigkeys/5.key")
            )
