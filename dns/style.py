# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import dataclasses
from typing import Any, TypeVar

T = TypeVar("T", bound="BaseStyle")


@dataclasses.dataclass
class BaseStyle:
    """All text styles"""

    @classmethod
    def from_keywords(cls: type[T], kw: dict[str, Any]) -> T:
        ok_kw: dict[str, Any] = {}
        for k, v in kw.items():
            if k == "chunksize":
                ok_kw["hex_chunk_size"] = v
                ok_kw["base64_chunk_size"] = v
            elif k == "separator":
                ok_kw["hex_separator"] = v
                ok_kw["base64_separator"] = v
            elif hasattr(cls, k):
                ok_kw[k] = v
        return cls(**ok_kw)
