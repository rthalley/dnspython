# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Internal text-processing helpers."""

import functools
import string

_ASCII_DIGITS = frozenset(string.digits)

_ALL_ASCII_DIGITS = string.digits + string.ascii_lowercase


def is_ascii_digit(c: str) -> bool:
    """Is *c* one of the ASCII digits "0" through "9"?

    Unlike ``str.isdigit()`` and ``str.isdecimal()``, this returns ``False``
    for non-ASCII digits such as U+0967 DEVANAGARI DIGIT ONE.
    """
    return c in _ASCII_DIGITS


@functools.cache
def _ascii_digits_for_base(base: int) -> frozenset[str]:
    if base < 2 or base > 36:
        raise ValueError(f"invalid base {base}")
    digits = _ALL_ASCII_DIGITS[:base]
    return frozenset(digits + digits.upper())


def is_ascii_digits(text: str, base: int = 10) -> bool:
    """Is *text* a non-empty string consisting only of ASCII digits valid in
    *base*?

    Digits greater than 9 are the ASCII letters, in either case, as with
    ``int()``.  Unlike ``int()``, a sign, whitespace, underscores, and base
    prefixes such as ``0x`` are not allowed.  Unlike ``str.isdigit()`` and
    ``str.isdecimal()``, non-ASCII digits such as U+0967 DEVANAGARI DIGIT ONE
    are not allowed.

    Raises ``ValueError`` if *base* is not between 2 and 36 inclusive.
    """
    if base == 10:
        return text.isascii() and text.isdecimal()
    digits = _ascii_digits_for_base(base)
    return len(text) > 0 and all(c in digits for c in text)
