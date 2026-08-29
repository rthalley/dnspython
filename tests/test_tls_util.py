# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pathlib
import ssl

import pytest

import dns._tls_util
import dns.query
from tests.util import here


def test_convert_verify_bool():
    assert dns._tls_util.convert_verify_to_cafile_and_capath(True) == (None, None)
    assert dns._tls_util.convert_verify_to_cafile_and_capath(False) == (None, None)


def test_convert_verify_str():
    cafile = here("tls/ca.crt")
    assert dns._tls_util.convert_verify_to_cafile_and_capath(cafile) == (cafile, None)
    capath = here("tls")
    assert dns._tls_util.convert_verify_to_cafile_and_capath(capath) == (None, capath)


def test_convert_verify_pathlike():
    cafile = pathlib.Path(here("tls/ca.crt"))
    assert dns._tls_util.convert_verify_to_cafile_and_capath(cafile) == (
        str(cafile),
        None,
    )
    capath = pathlib.Path(here("tls"))
    assert dns._tls_util.convert_verify_to_cafile_and_capath(capath) == (
        None,
        str(capath),
    )


def test_convert_verify_invalid():
    for bad in [here("tls/nonexistent"), pathlib.Path(here("tls/nonexistent"))]:
        with pytest.raises(ValueError):
            dns._tls_util.convert_verify_to_cafile_and_capath(bad)


def test_make_ssl_context_with_pathlike_verify():
    ctx = dns.query.make_ssl_context(verify=pathlib.Path(here("tls/ca.crt")))
    assert isinstance(ctx, ssl.SSLContext)
