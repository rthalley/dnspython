# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pytest

from dns._features import (
    _cache,
    _requirements,
    _tuple_from_text,
    _version_check,
    force,
    have,
)

try:
    import cryptography

    v = _tuple_from_text(cryptography.__version__)
    have_cryptography = v >= (42, 0, 0)
except ImportError:
    have_cryptography = False


def test_tuple_from_text():
    assert _tuple_from_text("") == ()
    assert _tuple_from_text("1") == (1,)
    assert _tuple_from_text("1.2") == (1, 2)
    assert _tuple_from_text("1.2rc1") == (1, 2)
    assert _tuple_from_text("1.2.junk3") == (1, 2)


@pytest.mark.skipif(
    not have_cryptography, reason="cryptography not available or too old"
)
def test_version_check():
    assert _version_check("cryptography>=42")
    assert not _version_check("cryptography>=10000")
    assert not _version_check("totallyboguspackagename>=10000")


@pytest.mark.skipif(
    not have_cryptography, reason="cryptography not available or too old"
)
def test_have():
    # ensure cache is empty; we can't just assign as our local is shadowing the
    # variable in dns._features
    while len(_cache) > 0:
        _cache.popitem()
    assert have("dnssec")
    assert _cache["dnssec"] == True
    assert not have("bogusfeature")
    assert _cache["bogusfeature"] == False
    _requirements["unavailable"] = ["bogusmodule>=10000"]
    try:
        assert not have("unavailable")
    finally:
        del _requirements["unavailable"]


def test_force():
    while len(_cache) > 0:
        _cache.popitem()
    assert not have("bogusfeature")
    assert _cache["bogusfeature"] == False
    force("bogusfeature", True)
    assert have("bogusfeature")
    assert _cache["bogusfeature"] == True
    force("bogusfeature", False)
    assert not have("bogusfeature")
    assert _cache["bogusfeature"] == False
    _requirements["unavailable"] = ["bogusmodule>=10000"]
    try:
        assert not have("unavailable")
        assert _cache["unavailable"] == False
        force("unavailable", True)
        assert _cache["unavailable"] == True
    finally:
        del _requirements["unavailable"]
