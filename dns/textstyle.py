# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import dataclasses

import dns.idnacodecs


@dataclasses.dataclass(frozen=True)
class TextStyle:
    # Name Styles
    idna_codec: dns.idnacodecs.IDNACodec | None = None
    # Rdata Styles
    txt_is_utf8: bool = False
    hex_chunk_size: int = 128
    hex_chunk_separator: bytes = b" "

    def replace(self, /, **changes) -> "TextStyle":
        return dataclasses.replace(self, **changes)


DEFAULT_TEXTSTYLE = TextStyle()
