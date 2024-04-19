# CopyrighAt (C) Dnspython Contributors, see LICENSE for text of ISC license

import os.path

import pytest

import dns.name
from dns.psl import PublicSuffixList
from tests.util import here, is_internet_reachable


def check_expectations(psl, tests, reduce=False):
    for input, expected in tests.items():
        is_idna = not dns.name.is_all_ascii(input)
        try:
            input_name = dns.name.from_text(input).canonicalize()
        except dns.name.EmptyLabel:
            # Some exceptions are expected as the test data has some
            # lines with domains starting with ".".  These will make us
            # throw an empty label exception, which is fine.
            assert expected == "exception"
            continue
        if reduce:
            output_name = psl.reduced_domain(input_name)
        else:
            output_name = psl.base_domain(input_name)
        if output_name is None:
            result = "none"
        else:
            if is_idna:
                result = output_name.to_unicode(True)
            else:
                result = output_name.to_text(True)
        assert result == expected
        if not reduce and output_name is not None:
            assert output_name.parent() == psl.public_suffix(input_name)


@pytest.mark.skipif(
    not (
        os.path.exists(here("real_psl.txt"))
        and os.path.exists(here("real_psl_tests.txt"))
    ),
    reason="Real PSL and/or tests not available",
)
def test_public_suffix_tests_with_real_psl():
    psl = PublicSuffixList(here("real_psl.txt"), download_if_needed=True)
    tests = {}
    with open(here("real_psl_tests.txt"), "r") as f:
        for l in f.readlines():
            if l == "":
                break
            l = l.rstrip()
            if l == "" or l.startswith("//"):
                continue
            parts = l.split()
            if len(parts) != 2:
                raise ValueError("split didn't result in two things")
            input = parts[0]
            expected = parts[1]
            if input.startswith("."):
                expected = "exception"
            if expected == "null":
                expected = "none"
            tests[input] = expected


def test_base_domain():
    psl = PublicSuffixList(here("psl_test.txt"))
    tests = {
        ".": "none",
        "com": "none",
        "bogus-tld": "none",
        "sub.bogus-tld": "sub.bogus-tld",
        "www.sub.bogus-tld": "sub.bogus-tld",
        "org": "none",
        "dnspython.org": "dnspython.org",
        "www.dnspython.org": "dnspython.org",
        "uk": "none",
        "sub.uk": "sub.uk",
        "www.sub.uk": "sub.uk",
        "co.uk": "none",
        "sub.co.uk": "sub.co.uk",
        "www.sub.co.uk": "sub.co.uk",
        "sub.sch.uk": "none",
        "sub.sub.sch.uk": "sub.sub.sch.uk",
        "www.sub.sub.sch.uk": "sub.sub.sch.uk",
        "exc.sch.uk": "exc.sch.uk",
    }
    check_expectations(psl, tests)


def test_strict_base_domain():
    psl = PublicSuffixList(here("psl_test.txt"), allow_unlisted_gtlds=False)
    tests = {
        ".": "none",
        "bogus-tld": "none",
        "sub.bogus-tld": "none",
        "www.sub.bogus-tld": "none",
        "org": "none",
        "dnspython.org": "dnspython.org",
        "www.dnspython.org": "dnspython.org",
    }
    check_expectations(psl, tests)


def test_reduced_name():
    psl = PublicSuffixList(here("psl_test.txt"))
    tests = {
        ".": ".",
        "bogus-tld": "bogus-tld",
        "sub.bogus-tld": "sub.bogus-tld",
        "www.sub.bogus-tld": "sub.bogus-tld",
        "org": "org",
        "dnspython.org": "dnspython.org",
        "www.dnspython.org": "dnspython.org",
    }
    check_expectations(psl, tests, True)
