# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2001-2017 Nominum, Inc.
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

"""Utilities for DNS Names."""

_escaped = b'"().;\\@$'
_escaped_text = '"().;\\@$'


def escapify(label: bytes | str) -> str:
    """Escape the characters in label which need it.
    @returns: the escaped string
    @rtype: string"""
    if isinstance(label, bytes):
        # Ordinary DNS label mode.  Escape special characters and values
        # < 0x20 or > 0x7f.
        text = ""
        for c in label:
            if c in _escaped:
                text += "\\" + chr(c)
            elif c > 0x20 and c < 0x7F:
                text += chr(c)
            else:
                text += f"\\{c:03d}"
        return text

    # Unicode label mode.  Escape only special characters and values < 0x20
    text = ""
    for uc in label:
        if uc in _escaped_text:
            text += "\\" + uc
        elif uc <= "\x20":
            text += f"\\{ord(uc):03d}"
        else:
            text += uc
    return text


def is_all_ascii(text: str) -> bool:
    for c in text:
        if ord(c) > 0x7F:
            return False
    return True
