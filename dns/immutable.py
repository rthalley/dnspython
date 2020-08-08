# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import collections.abc
import sys

if sys.version_info >= (3, 7):
    odict = dict
else:
    from collections import OrderedDict as odict  # pragma: no cover


class ImmutableDict(collections.abc.Mapping):
    def __init__(self, dictionary, no_copy=False):
        """Make an immutable dictionary from the specified dictionary.

        If *no_copy* is `True`, then *dictionary* will be wrapped instead
        of copied.  Only set this if you are sure there will be no external
        references to the dictionary.
        """
        if no_copy and isinstance(dictionary, odict):
            self._odict = dictionary
        else:
            self._odict = odict(dictionary)
        self._hash = None

    def __getitem__(self, key):
        return self._odict.__getitem__(key)

    def __hash__(self):
        if self._hash is None:
            self._hash = 0
            for key in sorted(self._odict.keys()):
                self._hash ^= hash(key)
        return self._hash

    def __len__(self):
        return len(self._odict)

    def __iter__(self):
        return iter(self._odict)


def constify(o):
    """
    Convert mutable types to immutable types.
    """
    if isinstance(o, bytearray):
        return bytes(o)
    if isinstance(o, tuple):
        try:
            hash(o)
            return o
        except Exception:
            return tuple(constify(elt) for elt in o)
    if isinstance(o, list):
        return tuple(constify(elt) for elt in o)
    if isinstance(o, dict):
        cdict = odict()
        for k, v in o.items():
            cdict[k] = constify(v)
        return ImmutableDict(cdict, True)
    return o
