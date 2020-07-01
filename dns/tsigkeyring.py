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

"""A place to store TSIG keys."""

import base64

import dns.name


def from_text(textring):
    """Convert a dictionary containing (textual DNS name, base64 secret)
    or (textual DNS name, (algorithm, base64 secret)) where algorithm
    can be a dns.name.Name or string into a binary keyring which has
    (dns.name.Name, dns.tsig.Key) pairs.
    @rtype: dict"""

    keyring = {}
    for (name, value) in textring.items():
        name = dns.name.from_text(name)
        if isinstance(value, str):
            algorithm = dns.tsig.default_algorithm
            secret = value
        else:
            (algorithm, secret) = value
            if isinstance(algorithm, str):
                algorithm = dns.name.from_text(algorithm)
        keyring[name] = dns.tsig.Key(name, secret, algorithm)
    return keyring


def to_text(keyring):
    """Convert a dictionary containing (dns.name.Name, dns.tsig.Key) pairs
    into a text keyring which has (textual DNS name, (textual algorithm,
    base64 secret)) pairs.
    @rtype: dict"""

    textring = {}
    for (name, key) in keyring.items():
        name = name.to_text()
        if isinstance(key, bytes):
            algorithm = dns.tsig.default_algorithm
            secret = key
        else:
            algorithm = key.algorithm
            secret = key.secret
        textring[name] = (algorithm.to_text(),
                          base64.encodebytes(secret).decode().rstrip())
    return textring
