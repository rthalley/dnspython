# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
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

"""DNS TTL conversion."""

import dns.exception

MAX_INTERVAL = 4294967295
MAX_TTL = 2147483647

class BadTTL(dns.exception.SyntaxError):
    """DNS TTL value is not well-formed."""


def interval_from_text(text, maximum=MAX_INTERVAL, description='interval',
                       exception=ValueError):
    """Convert the text form of a time interval to an integer.

    The BIND 8 units syntax for intervals (e.g. '1w6d4h3m10s') is supported.

    *text*, a ``str``, the textual interval.

    Raises *exception* if the interval is not well-formed.

    Returns an ``int``.
    """

    if text.isdigit():
        total = int(text)
    elif len(text) == 0:
        raise exception('empty string')
    else:
        total = 0
        current = 0
        need_digit = True
        for c in text:
            if c.isdigit():
                current *= 10
                current += int(c)
                need_digit = False
            else:
                if need_digit:
                    raise BadTTL
                c = c.lower()
                if c == 'w':
                    total += current * 604800
                elif c == 'd':
                    total += current * 86400
                elif c == 'h':
                    total += current * 3600
                elif c == 'm':
                    total += current * 60
                elif c == 's':
                    total += current
                else:
                    raise exception("unknown unit '%s'" % c)
                current = 0
                need_digit = True
        if not current == 0:
            raise exception("trailing integer")
    if total < 0 or total > maximum:
        raise exception(f'{description} should be between 0 and {maximum} '
                        '(inclusive)')
    return total

def from_text(text):
    return interval_from_text(text, MAX_TTL, 'TTL', BadTTL)

def make_interval(value, maximum=MAX_INTERVAL, description='interval',
                  exception=ValueError):
    if isinstance(value, int):
        if value < 0 or value > maximum:
            raise exception(f'{description} should be between 0 and {maximum} '
                            '(inclusive)')
        return value
    elif isinstance(value, str):
        return interval_from_text(value, maximum, description, exception)
    else:
        raise ValueError(f'cannot convert value to {description}')

def make(value):
    return make_interval(value, MAX_TTL, 'TTL', BadTTL)
