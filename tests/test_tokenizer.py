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

import dns.exception
import dns.tokenizer

Token = dns.tokenizer.Token

class TokenizerTestCase(unittest.TestCase):

    def testStr(self):
        tok = dns.tokenizer.Tokenizer('foo')
        token = tok.get()
        self.assertEqual(token, Token(dns.tokenizer.IDENTIFIER, 'foo'))

    def testQuotedString1(self):
        tok = dns.tokenizer.Tokenizer(r'"foo"')
        token = tok.get()
        self.assertEqual(token, Token(dns.tokenizer.QUOTED_STRING, 'foo'))

    def testQuotedString2(self):
        tok = dns.tokenizer.Tokenizer(r'""')
        token = tok.get()
        self.assertEqual(token, Token(dns.tokenizer.QUOTED_STRING, ''))

    def testQuotedString3(self):
        tok = dns.tokenizer.Tokenizer(r'"\"foo\""')
        token = tok.get()
        self.assertEqual(token, Token(dns.tokenizer.QUOTED_STRING, '\\"foo\\"'))

    def testQuotedString4(self):
        tok = dns.tokenizer.Tokenizer(r'"foo\010bar"')
        token = tok.get()
        self.assertEqual(token, Token(dns.tokenizer.QUOTED_STRING,
                                      'foo\\010bar'))

    def testQuotedString5(self):
        def bad():
            tok = dns.tokenizer.Tokenizer(r'"foo')
            tok.get()
        self.assertRaises(dns.exception.UnexpectedEnd, bad)

    def testQuotedString6(self):
        def bad():
            tok = dns.tokenizer.Tokenizer(r'"foo\01')
            tok.get()
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testQuotedString7(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('"foo\nbar"')
            tok.get()
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testEmpty1(self):
        tok = dns.tokenizer.Tokenizer('')
        token = tok.get()
        self.assertTrue(token.is_eof())

    def testEmpty2(self):
        tok = dns.tokenizer.Tokenizer('')
        token1 = tok.get()
        token2 = tok.get()
        self.assertTrue(token1.is_eof() and token2.is_eof())

    def testEOL(self):
        tok = dns.tokenizer.Tokenizer('\n')
        token1 = tok.get()
        token2 = tok.get()
        self.assertTrue(token1.is_eol() and token2.is_eof())

    def testWS1(self):
        tok = dns.tokenizer.Tokenizer(' \n')
        token1 = tok.get()
        self.assertTrue(token1.is_eol())

    def testWS2(self):
        tok = dns.tokenizer.Tokenizer(' \n')
        token1 = tok.get(want_leading=True)
        self.assertTrue(token1.is_whitespace())

    def testComment1(self):
        tok = dns.tokenizer.Tokenizer(' ;foo\n')
        token1 = tok.get()
        self.assertTrue(token1.is_eol())

    def testComment2(self):
        tok = dns.tokenizer.Tokenizer(' ;foo\n')
        token1 = tok.get(want_comment=True)
        token2 = tok.get()
        self.assertEqual(token1, Token(dns.tokenizer.COMMENT, 'foo'))
        self.assertTrue(token2.is_eol())

    def testComment3(self):
        tok = dns.tokenizer.Tokenizer(' ;foo bar\n')
        token1 = tok.get(want_comment=True)
        token2 = tok.get()
        self.assertEqual(token1, Token(dns.tokenizer.COMMENT, 'foo bar'))
        self.assertTrue(token2.is_eol())

    def testMultiline1(self):
        tok = dns.tokenizer.Tokenizer('( foo\n\n bar\n)')
        tokens = list(iter(tok))
        self.assertEqual(tokens, [Token(dns.tokenizer.IDENTIFIER, 'foo'),
                                  Token(dns.tokenizer.IDENTIFIER, 'bar')])

    def testMultiline2(self):
        tok = dns.tokenizer.Tokenizer('( foo\n\n bar\n)\n')
        tokens = list(iter(tok))
        self.assertEqual(tokens, [Token(dns.tokenizer.IDENTIFIER, 'foo'),
                                  Token(dns.tokenizer.IDENTIFIER, 'bar'),
                                  Token(dns.tokenizer.EOL, '\n')])
    def testMultiline3(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('foo)')
            list(iter(tok))
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testMultiline4(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('((foo)')
            list(iter(tok))
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testUnget1(self):
        tok = dns.tokenizer.Tokenizer('foo')
        t1 = tok.get()
        tok.unget(t1)
        t2 = tok.get()
        self.assertEqual(t1, t2)
        self.assertEqual(t1.ttype, dns.tokenizer.IDENTIFIER)
        self.assertEqual(t1.value, 'foo')

    def testUnget2(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('foo')
            t1 = tok.get()
            tok.unget(t1)
            tok.unget(t1)
        self.assertRaises(dns.tokenizer.UngetBufferFull, bad)

    def testGetEOL1(self):
        tok = dns.tokenizer.Tokenizer('\n')
        t = tok.get_eol()
        self.assertEqual(t, '\n')

    def testGetEOL2(self):
        tok = dns.tokenizer.Tokenizer('')
        t = tok.get_eol()
        self.assertEqual(t, '')

    def testEscapedDelimiter1(self):
        tok = dns.tokenizer.Tokenizer(r'ch\ ld')
        t = tok.get()
        self.assertEqual(t.ttype, dns.tokenizer.IDENTIFIER)
        self.assertEqual(t.value, r'ch\ ld')

    def testEscapedDelimiter2(self):
        tok = dns.tokenizer.Tokenizer(r'ch\032ld')
        t = tok.get()
        self.assertEqual(t.ttype, dns.tokenizer.IDENTIFIER)
        self.assertEqual(t.value, r'ch\032ld')

    def testEscapedDelimiter3(self):
        tok = dns.tokenizer.Tokenizer(r'ch\ild')
        t = tok.get()
        self.assertEqual(t.ttype, dns.tokenizer.IDENTIFIER)
        self.assertEqual(t.value, r'ch\ild')

    def testEscapedDelimiter1u(self):
        tok = dns.tokenizer.Tokenizer(r'ch\ ld')
        t = tok.get().unescape()
        self.assertEqual(t.ttype, dns.tokenizer.IDENTIFIER)
        self.assertEqual(t.value, r'ch ld')

    def testEscapedDelimiter2u(self):
        tok = dns.tokenizer.Tokenizer(r'ch\032ld')
        t = tok.get().unescape()
        self.assertEqual(t.ttype, dns.tokenizer.IDENTIFIER)
        self.assertEqual(t.value, 'ch ld')

    def testEscapedDelimiter3u(self):
        tok = dns.tokenizer.Tokenizer(r'ch\ild')
        t = tok.get().unescape()
        self.assertEqual(t.ttype, dns.tokenizer.IDENTIFIER)
        self.assertEqual(t.value, r'child')

    def testGetUInt(self):
        tok = dns.tokenizer.Tokenizer('1234')
        v = tok.get_int()
        self.assertEqual(v, 1234)
        def bad1():
            tok = dns.tokenizer.Tokenizer('"1234"')
            v = tok.get_int()
        self.assertRaises(dns.exception.SyntaxError, bad1)
        def bad2():
            tok = dns.tokenizer.Tokenizer('q1234')
            v = tok.get_int()
        self.assertRaises(dns.exception.SyntaxError, bad2)
        def bad3():
            tok = dns.tokenizer.Tokenizer('4294967296')
            v = tok.get_uint32()
        self.assertRaises(dns.exception.SyntaxError, bad3)
        def bad4():
            tok = dns.tokenizer.Tokenizer('65536')
            v = tok.get_uint16()
        self.assertRaises(dns.exception.SyntaxError, bad4)
        def bad5():
            tok = dns.tokenizer.Tokenizer('256')
            v = tok.get_uint8()
        self.assertRaises(dns.exception.SyntaxError, bad5)
        # Even though it is badly named get_int(), it's really get_unit!
        def bad6():
            tok = dns.tokenizer.Tokenizer('-1234')
            v = tok.get_int()
        self.assertRaises(dns.exception.SyntaxError, bad5)

    def testGetString(self):
        tok = dns.tokenizer.Tokenizer('foo')
        v = tok.get_string()
        self.assertEqual(v, 'foo')
        tok = dns.tokenizer.Tokenizer('"foo"')
        v = tok.get_string()
        self.assertEqual(v, 'foo')
        tok = dns.tokenizer.Tokenizer('abcdefghij')
        v = tok.get_string(max_length=10)
        self.assertEqual(v, 'abcdefghij')
        def bad():
            tok = dns.tokenizer.Tokenizer('abcdefghij')
            v = tok.get_string(max_length=9)
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testMultiLineWithComment(self):
        tok = dns.tokenizer.Tokenizer('( ; abc\n)')
        tok.get_eol()
        # Nothing to assert here, as we're testing tok.get_eol() does NOT
        # raise.

    def testEOLAfterComment(self):
        tok = dns.tokenizer.Tokenizer('; abc\n')
        t = tok.get()
        self.assertTrue(t.is_eol())

    def testEOFAfterComment(self):
        tok = dns.tokenizer.Tokenizer('; abc')
        t = tok.get()
        self.assertTrue(t.is_eof())

    def testMultiLineWithEOFAfterComment(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('( ; abc')
            tok.get_eol()
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testEscapeUnexpectedEnd(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('\\')
            tok.get()
        self.assertRaises(dns.exception.UnexpectedEnd, bad)

    def testGetUngetRegetComment(self):
        tok = dns.tokenizer.Tokenizer(';comment')
        t1 = tok.get(want_comment=True)
        tok.unget(t1)
        t2 = tok.get(want_comment=True)
        self.assertEqual(t1, t2)

    def testBadAsName(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('"not an identifier"')
            t = tok.get()
            tok.as_name(t)
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testBadGetTTL(self):
        def bad():
            tok = dns.tokenizer.Tokenizer('"not an identifier"')
            v = tok.get_ttl()
        self.assertRaises(dns.exception.SyntaxError, bad)

    def testDanglingEscapes(self):
        def bad1():
            tok = dns.tokenizer.Tokenizer('"\\"')
            t = tok.get().unescape()
        self.assertRaises(dns.exception.SyntaxError, bad1)
        def bad2():
            tok = dns.tokenizer.Tokenizer('"\\0"')
            t = tok.get().unescape()
        self.assertRaises(dns.exception.SyntaxError, bad2)
        def bad3():
            tok = dns.tokenizer.Tokenizer('"\\00"')
            t = tok.get().unescape()
        self.assertRaises(dns.exception.SyntaxError, bad3)
        def bad4():
            tok = dns.tokenizer.Tokenizer('"\\"')
            t = tok.get().unescape_to_bytes()
        self.assertRaises(dns.exception.SyntaxError, bad4)
        def bad5():
            tok = dns.tokenizer.Tokenizer('"\\0"')
            t = tok.get().unescape_to_bytes()
        self.assertRaises(dns.exception.SyntaxError, bad5)
        def bad6():
            tok = dns.tokenizer.Tokenizer('"\\00"')
            t = tok.get().unescape_to_bytes()
        self.assertRaises(dns.exception.SyntaxError, bad6)
        def bad7():
            tok = dns.tokenizer.Tokenizer('"\\00a"')
            t = tok.get().unescape()
        self.assertRaises(dns.exception.SyntaxError, bad7)
        def bad8():
            tok = dns.tokenizer.Tokenizer('"\\00a"')
            t = tok.get().unescape_to_bytes()
        self.assertRaises(dns.exception.SyntaxError, bad8)

if __name__ == '__main__':
    unittest.main()
