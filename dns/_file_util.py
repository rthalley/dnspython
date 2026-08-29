# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import contextlib
import os
from typing import IO, Any, cast


def as_filename(f: object) -> str | None:
    if isinstance(f, (str, os.PathLike)):
        return os.fsdecode(f)
    return None


def maybe_open(
    f: str | os.PathLike | IO[Any], mode: str = "r", encoding: str | None = None
) -> contextlib.AbstractContextManager[IO[Any]]:
    filename = as_filename(f)
    if filename is not None:
        return open(filename, mode, encoding=encoding)
    # as_filename() is not a type guard, so narrow f by hand
    return contextlib.nullcontext(cast(IO[Any], f))
