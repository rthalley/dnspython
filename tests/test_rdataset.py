# -*- coding: utf-8
# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

import dns.name
import dns.rdataset

class RdatasetTestCase(unittest.TestCase):

    def testCodec2003(self):
        r1 = dns.rdataset.from_text_list('in', 'ns', 30,
                                         ['Königsgäßchen'])
        r2 = dns.rdataset.from_text_list('in', 'ns', 30,
                                         ['xn--knigsgsschen-lcb0w'])
        self.assertEqual(r1, r2)

    def testCodec2008(self):
        r1 = dns.rdataset.from_text_list('in', 'ns', 30,
                                         ['Königsgäßchen'],
                                         idna_codec=dns.name.IDNA_2008)
        r2 = dns.rdataset.from_text_list('in', 'ns', 30,
                                         ['xn--knigsgchen-b4a3dun'],
                                         idna_codec=dns.name.IDNA_2008)
        self.assertEqual(r1, r2)

if __name__ == '__main__':
    unittest.main()
