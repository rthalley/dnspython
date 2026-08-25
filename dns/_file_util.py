# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import contextlib
import os
from typing import Any


def as_filename(f: Any) -> str | None:
    if isinstance(f, (str, os.PathLike)):
        return os.fsdecode(f)
    return None


def maybe_open(
    f: Any, mode: str = "r", encoding: str | None = None
) -> contextlib.AbstractContextManager:
    filename = as_filename(f)
    if filename is not None:
        return open(filename, mode, encoding=encoding)
    return contextlib.nullcontext(f)
