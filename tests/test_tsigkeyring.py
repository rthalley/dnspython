# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import base64
import unittest

import dns.tsigkeyring

text_keyring = {
    'keyname.' : 'NjHwPsMKjdN++dOfE5iAiQ=='
}

rich_keyring = {
    dns.name.from_text('keyname.') : \
    base64.decodebytes('NjHwPsMKjdN++dOfE5iAiQ=='.encode())
}

class TSIGKeyRingTestCase(unittest.TestCase):

    def test_from_text(self):
        """text keyring -> rich keyring"""
        rkeyring = dns.tsigkeyring.from_text(text_keyring)
        self.assertEqual(rkeyring, rich_keyring)

    def test_to_text(self):
        """text keyring -> rich keyring -> text keyring"""
        tkeyring = dns.tsigkeyring.to_text(rich_keyring)
        self.assertEqual(tkeyring, text_keyring)

    def test_from_and_to_text(self):
        """text keyring -> rich keyring -> text keyring"""
        rkeyring = dns.tsigkeyring.from_text(text_keyring)
        tkeyring = dns.tsigkeyring.to_text(rkeyring)
        self.assertEqual(tkeyring, text_keyring)
