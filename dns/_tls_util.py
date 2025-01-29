# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import os
from typing import Optional, Tuple, Union


def convert_verify_to_cafile_and_capath(
    verify: Union[bool, str],
) -> Tuple[Optional[str], Optional[str]]:
    cafile: Optional[str] = None
    capath: Optional[str] = None
    if isinstance(verify, str):
        if os.path.isfile(verify):
            cafile = verify
        elif os.path.isdir(verify):
            capath = verify
        else:
            raise ValueError("invalid verify string")
    return cafile, capath
