# Copyright (C) 2011 Nominum, Inc.
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

"""Miscellaneous Implementation Helpers"""

import struct

def cmp(x, y):
    """The cmp() function from Python 2"""
    if x > y:
        return 1
    elif x < y:
        return -1
    else:
        return 0

def write_uint8(bfile, value):
    """Write an unsigned 8-bit integer to an io.BytesIO file
    """
    bfile.write(struct.pack('B', value))


def write_uint16(bfile, value):
    """Write an unsigned 16-bit integer to an io.BytesIO file
    """
    bfile.write(struct.pack('!H', value))

def write_uint32(bfile, value):
    """Write an unsigned 32-bit integer to an io.BytesIO file
    """
    bfile.write(struct.pack('!L', value))


def write_uint64(bfile, value):
    """Write an unsigned 64-bit integer to an io.BytesIO file
    """
    bfile.write(struct.pack('!Q', value))
