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

import unittest
import binascii

import dns.update
import dns.rdata
import dns.rdataset
import dns.tsigkeyring

def hextowire(hex):
    return binascii.unhexlify(hex.replace(' ', '').encode())

goodwire = hextowire(
    '0001 2800 0001 0005 0007 0000'
    '076578616d706c6500 0006 0001'
    '03666f6fc00c 00ff 00ff 00000000 0000'
    'c019 0001 00ff 00000000 0000'
    '03626172c00c 0001 0001 00000000 0004 0a000005'
    '05626c617a32c00c 00ff 00fe 00000000 0000'
    'c049 0001 00fe 00000000 0000'
    'c019 0001 00ff 00000000 0000'
    'c019 0001 0001 0000012c 0004 0a000001'
    'c019 0001 0001 0000012c 0004 0a000002'
    'c035 0001 0001 0000012c 0004 0a000003'
    'c035 0001 00fe 00000000 0004 0a000004'
    '04626c617ac00c 0001 00ff 00000000 0000'
    'c049 00ff 00ff 00000000 0000'
)

goodwirenone = hextowire(
    '0001 2800 0001 0000 0001 0000'
    '076578616d706c6500 0006 0001'
    '03666f6fc00c 0001 00fe 00000000 0004 01020304'
)

badwirenone = hextowire(
    '0001 2800 0001 0003 0000 0000'
    '076578616d706c6500 0006 0001'
    '03666f6fc00c 00ff 00ff 00000000 0000'
    'c019 0001 00ff 00000000 0000'
    'c019 0001 00fe 00000000 0004 01020304'
)

badwireany = hextowire(
    '0001 2800 0001 0002 0000 0000'
    '076578616d706c6500 0006 0001'
    '03666f6fc00c 00ff 00ff 00000000 0000'
    'c019 0001 00ff 00000000 0004 01020304'
)

badwireanyany = hextowire(
    '0001 2800 0001 0001 0000 0000'
    '076578616d706c6500 0006 0001'
    '03666f6fc00c 00ff 00ff 00000000 0004 01020304'
)

badwirezonetype = hextowire(
    '0001 2800 0001 0000 0000 0000'
    '076578616d706c6500 0001 0001'
)

badwirezoneclass = hextowire(
    '0001 2800 0001 0000 0000 0000'
    '076578616d706c6500 0006 00ff'
)

badwirezonemulti = hextowire(
    '0001 2800 0002 0000 0000 0000'
    '076578616d706c6500 0006 0001'
    'c019 0006 0001'
)

badwirenozone = hextowire(
    '0001 2800 0000 0000 0001 0000'
    '03666f6f076578616d706c6500 0001 0001 00000030 0004 01020304'
)

update_text = """id 1
opcode UPDATE
rcode NOERROR
;ZONE
example. IN SOA
;PREREQ
foo ANY ANY
foo ANY A
bar 0 IN A 10.0.0.5
blaz2 NONE ANY
blaz2 NONE A
;UPDATE
foo ANY A
foo 300 IN A 10.0.0.1
foo 300 IN A 10.0.0.2
bar 300 IN A 10.0.0.3
bar 0 NONE A 10.0.0.4
blaz ANY A
blaz2 ANY ANY
"""

class UpdateTestCase(unittest.TestCase):

    def test_to_wire1(self): # type: () -> None
        update = dns.update.Update('example')
        update.id = 1
        update.present('foo')
        update.present('foo', 'a')
        update.present('bar', 'a', '10.0.0.5')
        update.absent('blaz2')
        update.absent('blaz2', 'a')
        update.replace('foo', 300, 'a', '10.0.0.1', '10.0.0.2')
        update.add('bar', 300, 'a', '10.0.0.3')
        update.delete('bar', 'a', '10.0.0.4')
        update.delete('blaz', 'a')
        update.delete('blaz2')
        self.assertEqual(update.to_wire(), goodwire)

    def test_to_wire2(self): # type: () -> None
        update = dns.update.Update('example')
        update.id = 1
        update.present('foo')
        update.present('foo', 'a')
        update.present('bar', 'a', '10.0.0.5')
        update.absent('blaz2')
        update.absent('blaz2', 'a')
        update.replace('foo', 300, 'a', '10.0.0.1', '10.0.0.2')
        update.add('bar', 300, dns.rdata.from_text(1, 1, '10.0.0.3'))
        update.delete('bar', 'a', '10.0.0.4')
        update.delete('blaz', 'a')
        update.delete('blaz2')
        self.assertEqual(update.to_wire(), goodwire)

    def test_to_wire3(self): # type: () -> None
        update = dns.update.Update('example')
        update.id = 1
        update.present('foo')
        update.present('foo', 'a')
        update.present('bar', 'a', '10.0.0.5')
        update.absent('blaz2')
        update.absent('blaz2', 'a')
        update.replace('foo', 300, 'a', '10.0.0.1', '10.0.0.2')
        update.add('bar', dns.rdataset.from_text(1, 1, 300, '10.0.0.3'))
        update.delete('bar', 'a', '10.0.0.4')
        update.delete('blaz', 'a')
        update.delete('blaz2')
        self.assertEqual(update.to_wire(), goodwire)

    def test_from_text1(self): # type: () -> None
        update = dns.message.from_text(update_text)
        self.assertTrue(isinstance(update, dns.update.UpdateMessage))
        w = update.to_wire(origin=dns.name.from_text('example'),
                           want_shuffle=False)
        self.assertEqual(w, goodwire)

    def test_from_wire(self):
        origin = dns.name.from_text('example')
        u1 = dns.message.from_wire(goodwire, origin=origin)
        u2 = dns.message.from_text(update_text, origin=origin)
        self.assertEqual(u1, u2)

    def test_good_explicit_delete_wire(self):
        name = dns.name.from_text('foo.example')
        u = dns.message.from_wire(goodwirenone)
        print(u)
        self.assertEqual(u.update[0].name, name)
        self.assertEqual(u.update[0].rdtype, dns.rdatatype.A)
        self.assertEqual(u.update[0].rdclass, dns.rdataclass.IN)
        self.assertTrue(u.update[0].deleting)
        self.assertEqual(u.update[0][0].address, '1.2.3.4')

    def test_none_with_rdata_from_wire(self):
        def bad():
            dns.message.from_wire(badwirenone)
        self.assertRaises(dns.exception.FormError, bad)

    def test_any_with_rdata_from_wire(self):
        def bad():
            dns.message.from_wire(badwireany)
        self.assertRaises(dns.exception.FormError, bad)

    def test_any_any_with_rdata_from_wire(self):
        def bad():
            dns.message.from_wire(badwireanyany)
        self.assertRaises(dns.exception.FormError, bad)

    def test_bad_zone_type_from_wire(self):
        def bad():
            dns.message.from_wire(badwirezonetype)
        self.assertRaises(dns.exception.FormError, bad)

    def test_bad_zone_class_from_wire(self):
        def bad():
            dns.message.from_wire(badwirezoneclass)
        self.assertRaises(dns.exception.FormError, bad)

    def test_bad_zone_multi_from_wire(self):
        def bad():
            dns.message.from_wire(badwirezonemulti)
        self.assertRaises(dns.exception.FormError, bad)

    def test_no_zone_section_from_wire(self):
        def bad():
            dns.message.from_wire(badwirenozone)
        self.assertRaises(dns.exception.FormError, bad)

    def test_TSIG(self):
        keyring = dns.tsigkeyring.from_text({
            'keyname.' : 'NjHwPsMKjdN++dOfE5iAiQ=='
        })
        update = dns.update.Update('example.', keyring=keyring)
        update.replace('host.example.', 300, 'A', '1.2.3.4')
        wire = update.to_wire()
        update2 = dns.message.from_wire(wire, keyring)
        self.assertEqual(update, update2)

if __name__ == '__main__':
    unittest.main()
