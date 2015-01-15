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

"""Common DNS Exceptions."""

class DNSException(Exception):
    """Abstract base class shared by all dnspython exceptions."""
    def __init__(self, *args):
        if args:
            super(DNSException, self).__init__(*args)
        else:
            # doc string is better implicit message than empty string
            super(DNSException, self).__init__(self.__doc__)

class FormError(DNSException):
    """DNS message is malformed."""
    pass

class SyntaxError(DNSException):
    """Text input is malformed."""
    pass

class UnexpectedEnd(SyntaxError):
    """Text input ended unexpectedly."""
    pass

class TooBig(DNSException):
    """The DNS message is too big."""
    pass

class Timeout(DNSException):
    """The DNS operation timed out."""
    pass
