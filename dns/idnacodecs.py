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

import encodings.idna  # pyright: ignore

import dns._features
import dns.exception
from dns._name_util import escapify, is_all_ascii

# Dnspython will never access idna if the import fails, but pyright can't figure
# that out, so...
#
# pyright: reportAttributeAccessIssue = false, reportPossiblyUnboundVariable = false

if dns._features.have("idna"):
    import idna  # pyright: ignore

    have_idna_2008 = True
else:  # pragma: no cover
    have_idna_2008 = False


class NoIDNA2008(dns.exception.DNSException):
    """IDNA 2008 processing was requested but the idna module is not
    available."""


class IDNAException(dns.exception.DNSException):
    """IDNA processing raised an exception."""

    supp_kwargs = {"idna_exception"}
    fmt = "IDNA processing exception: {idna_exception}"

    # We do this as otherwise mypy complains about unexpected keyword argument
    # idna_exception
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class IDNACodec:
    """Abstract base class for IDNA encoder/decoders."""

    def __init__(self):
        pass

    def is_idna(self, label: bytes) -> bool:
        return label.lower().startswith(b"xn--")

    def encode(self, label: str) -> bytes:
        raise NotImplementedError  # pragma: no cover

    def decode(self, label: bytes) -> str:
        # We do not apply any IDNA policy on decode.
        if self.is_idna(label):
            try:
                slabel = label[4:].decode("punycode")
                return escapify(slabel)
            except Exception as e:
                raise IDNAException(idna_exception=e)
        else:
            return escapify(label)


class IDNA2003Codec(IDNACodec):
    """IDNA 2003 encoder/decoder."""

    def __init__(self, strict_decode: bool = False):
        """Initialize the IDNA 2003 encoder/decoder.

        *strict_decode* is a ``bool``. If `True`, then IDNA2003 checking
        is done when decoding.  This can cause failures if the name
        was encoded with IDNA2008.  The default is `False`.
        """

        super().__init__()
        self.strict_decode = strict_decode

    def encode(self, label: str) -> bytes:
        """Encode *label*."""

        if label == "":
            return b""
        try:
            return encodings.idna.ToASCII(label)
        except UnicodeError:
            raise dns.exception.LabelTooLong

    def decode(self, label: bytes) -> str:
        """Decode *label*."""
        if not self.strict_decode:
            return super().decode(label)
        if label == b"":
            return ""
        try:
            return escapify(encodings.idna.ToUnicode(label))
        except Exception as e:
            raise IDNAException(idna_exception=e)


class IDNA2008Codec(IDNACodec):
    """IDNA 2008 encoder/decoder."""

    def __init__(
        self,
        uts_46: bool = False,
        transitional: bool = False,
        allow_pure_ascii: bool = False,
        strict_decode: bool = False,
    ):
        """Initialize the IDNA 2008 encoder/decoder.

        *uts_46* is a ``bool``.  If True, apply Unicode IDNA
        compatibility processing as described in Unicode Technical
        Standard #46 (https://unicode.org/reports/tr46/).
        If False, do not apply the mapping.  The default is False.

        *transitional* is a ``bool``: If True, use the
        "transitional" mode described in Unicode Technical Standard
        #46.  The default is False.  This setting has no effect
        in idna 3.11 and later as transitional support has been removed.

        *allow_pure_ascii* is a ``bool``.  If True, then a label which
        consists of only ASCII characters is allowed.  This is less
        strict than regular IDNA 2008, but is also necessary for mixed
        names, e.g. a name with starting with "_sip._tcp." and ending
        in an IDN suffix which would otherwise be disallowed.  The
        default is False.

        *strict_decode* is a ``bool``: If True, then IDNA2008 checking
        is done when decoding.  This can cause failures if the name
        was encoded with IDNA2003.  The default is False.
        """
        super().__init__()
        self.uts_46 = uts_46
        self.transitional = transitional
        self.allow_pure_ascii = allow_pure_ascii
        self.strict_decode = strict_decode

    def encode(self, label: str) -> bytes:
        if label == "":
            return b""
        if self.allow_pure_ascii and is_all_ascii(label):
            encoded = label.encode("ascii")
            if len(encoded) > 63:
                raise dns.exception.LabelTooLong
            return encoded
        if not have_idna_2008:
            raise NoIDNA2008
        try:
            if self.uts_46:
                # pylint: disable=possibly-used-before-assignment
                label = idna.uts46_remap(label, False, self.transitional)
            return idna.alabel(label)
        except idna.IDNAError as e:
            if e.args[0] == "Label too long":
                raise dns.exception.LabelTooLong
            else:
                raise IDNAException(idna_exception=e)

    def decode(self, label: bytes) -> str:
        if not self.strict_decode:
            return super().decode(label)
        if label == b"":
            return ""
        if not have_idna_2008:
            raise NoIDNA2008
        try:
            ulabel = idna.ulabel(label)
            if self.uts_46:
                ulabel = idna.uts46_remap(ulabel, False, self.transitional)
            return escapify(ulabel)
        except (idna.IDNAError, UnicodeError) as e:
            raise IDNAException(idna_exception=e)


IDNA_2003_Practical = IDNA2003Codec(False)
IDNA_2003_Strict = IDNA2003Codec(True)
IDNA_2003 = IDNA_2003_Practical
IDNA_2008_Practical = IDNA2008Codec(True, False, True, False)
IDNA_2008_UTS_46 = IDNA2008Codec(True, False, False, False)
IDNA_2008_Strict = IDNA2008Codec(False, False, False, True)
IDNA_2008_Transitional = IDNA2008Codec(True, True, False, False)
IDNA_2008 = IDNA_2008_Practical

if have_idna_2008:
    IDNA_DEFAULT = IDNA_2008_Practical
else:
    IDNA_DEFAULT = IDNA_2003_Practical


def set_default_idna_codec(idna_codec: IDNACodec):
    """Set the default IDNA codec."""
    global IDNA_DEFAULT
    IDNA_DEFAULT = idna_codec
