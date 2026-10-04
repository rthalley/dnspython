# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Text parsers must only accept ASCII digits as numbers.  Python's
# str.isdecimal() and int() also accept non-ASCII decimal digits, such as
# U+0661 ARABIC-INDIC DIGIT ONE, so each of these inputs used to be accepted.

import socket

import pytest

import dns._text_util
import dns.e164
import dns.exception
import dns.flags
import dns.grange
import dns.inet
import dns.message
import dns.rdata
import dns.rdatatype
import dns.tokenizer
import dns.ttl
from dns.rdtypes.rrsigbase import BadSigTime, sigtime_to_posixtime

ONE = "\u0661"  # ARABIC-INDIC DIGIT ONE


def test_is_ascii_digit():
    for c in "0123456789":
        assert dns._text_util.is_ascii_digit(c)
    for c in ["a", " ", "", ONE, "१", "²", "12"]:
        assert not dns._text_util.is_ascii_digit(c)


def test_is_ascii_digits():
    assert dns._text_util.is_ascii_digits("0123456789")
    for text in ["", "1a", " 1", "+1", "1_0", ONE, "1" + ONE, "²"]:
        assert not dns._text_util.is_ascii_digits(text)


@pytest.mark.parametrize("text", [ONE * 2, "1h" + ONE + "m"])
def test_ttl(text):
    with pytest.raises(dns.ttl.BadTTL):
        dns.ttl.from_text(text)


def test_grange():
    with pytest.raises(dns.exception.SyntaxError):
        dns.grange.from_text("1-" + ONE)


def test_e164():
    # Non-ASCII digits are dropped like any other non-digit.
    assert dns.e164.from_e164("+1" + ONE) == dns.e164.from_e164("+1")


def test_inet_scope():
    # The scope is not numeric, so it is looked up as an interface name.
    with pytest.raises(OSError):
        dns.inet.low_level_address_tuple(("fe80::1%" + ONE, 53), socket.AF_INET6)


def test_flags():
    with pytest.raises(KeyError):
        dns.flags.from_text("FLAG" + ONE)


def test_enum():
    with pytest.raises(dns.rdatatype.UnknownRdatatype):
        dns.rdatatype.from_text("TYPE" + ONE)


@pytest.mark.parametrize("text", [ONE * 10, "2020010100000" + ONE, "2020010100000+"])
def test_sigtime(text):
    with pytest.raises(BadSigTime):
        sigtime_to_posixtime(text)


@pytest.mark.parametrize("text", ["10.0.0.1 " + ONE + " 25", "10.0.0.1 6 2" + ONE])
def test_wks(text):
    with pytest.raises(dns.exception.SyntaxError):
        dns.rdata.from_text("IN", "WKS", text)


@pytest.mark.parametrize(
    "text",
    [
        "60 " + ONE + " 34.2 N 24 39 0.000 E 0",
        "60 9 3" + ONE + " N 24 39 0 E 0",
        "60 9 3" + ONE + ".2 N 24 39 0.000 E 0",
        "60 9 34." + ONE + " N 24 39 0.000 E 0",
        "60 9 34.2 N 24 " + ONE + " 0.000 E 0",
        "60 9 34 N 24 39 " + ONE + " E 0",
        "60 9 34.2 N 24 39 " + ONE + ".000 E 0",
        "60 9 34.2 N 24 39 0." + ONE + " E 0",
    ],
)
def test_loc(text):
    with pytest.raises(dns.exception.SyntaxError):
        dns.rdata.from_text("IN", "LOC", text)


def test_is_ascii_digits_base():
    assert dns._text_util.is_ascii_digits("17", 8)
    assert not dns._text_util.is_ascii_digits("18", 8)
    assert dns._text_util.is_ascii_digits("09afAF", 16)
    assert dns._text_util.is_ascii_digits("zZ", 36)
    for text in ["", "0x1f", "+1f", "1_f", ONE]:
        assert not dns._text_util.is_ascii_digits(text, 16)
    for base in [0, 1, 37]:
        with pytest.raises(ValueError):
            dns._text_util.is_ascii_digits("1", base)


@pytest.mark.parametrize("text", [ONE, "1" + ONE, "+1", "-1", "1_0", "0x10"])
def test_tokenizer_int(text):
    with pytest.raises(dns.exception.SyntaxError):
        dns.tokenizer.Tokenizer(text).get_int()


def test_tokenizer_int_base():
    assert dns.tokenizer.Tokenizer("17").get_int(base=8) == 15
    assert dns.tokenizer.Tokenizer("1f").get_int(base=16) == 31
    for text in ["18", "0o17"]:
        with pytest.raises(dns.exception.SyntaxError):
            dns.tokenizer.Tokenizer(text).get_int(base=8)


@pytest.mark.parametrize("text", [ONE + "0", "+10"])
def test_rdata_int(text):
    with pytest.raises(dns.exception.SyntaxError):
        dns.rdata.from_text("IN", "MX", text + " mail.example.")


def test_message_ttl():
    def rrset(ttl):
        m = dns.message.from_text(f"id 1\n;ANSWER\nexample. {ttl} IN A 10.0.0.1\n")
        return m.answer[0]

    assert rrset("300").ttl == 300
    # Base 10, so a leading zero is allowed.
    assert rrset("010").ttl == 10
    for ttl in [ONE, "0x10", "+10"]:
        with pytest.raises(dns.exception.DNSException):
            rrset(ttl)


def test_message_no_ttl():
    m = dns.message.from_text("id 1\n;ANSWER\nexample. IN A 10.0.0.1\n")
    assert m.answer[0].ttl == 0


@pytest.mark.parametrize("port", [ONE, "+53", "5_3"])
def test_svcb_port(port):
    with pytest.raises(dns.exception.SyntaxError):
        dns.rdata.from_text("IN", "SVCB", f"1 . port={port}")
