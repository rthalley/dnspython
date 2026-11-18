# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import contextlib
import os
import sys
from typing import IO, Any, cast


def as_filename(f: object) -> str | None:
    if isinstance(f, (str, os.PathLike)):
        return os.fsdecode(f)
    return None


def maybe_open(
    f: str | os.PathLike | IO[Any],
    mode: str = "r",
    encoding: str | None = None,
    chmod: int | None = None,
) -> contextlib.AbstractContextManager[IO[Any]]:
    filename = as_filename(f)
    if filename is not None:
        if chmod is not None:
            fd = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, chmod)
            # os.open() only applies the mode when it creates the file, so set
            # it explicitly in case the file already existed.
            if sys.platform != "win32":
                try:
                    os.fchmod(fd, chmod)
                except BaseException:  # pragma: no cover
                    os.close(fd)
                    raise
            return open(fd, mode, encoding=encoding)
        return open(filename, mode, encoding=encoding)
    # as_filename() is not a type guard, so narrow f by hand
    return contextlib.nullcontext(cast(IO[Any], f))
