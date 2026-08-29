# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import os

import dns._file_util


def convert_verify_to_cafile_and_capath(
    verify: bool | str | os.PathLike,
) -> tuple[str | None, str | None]:
    cafile: str | None = None
    capath: str | None = None
    filename = dns._file_util.as_filename(verify)
    if filename is not None:
        if os.path.isfile(filename):
            cafile = filename
        elif os.path.isdir(filename):
            capath = filename
        else:
            raise ValueError("invalid verify string")
    return cafile, capath
