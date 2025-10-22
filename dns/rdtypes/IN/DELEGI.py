# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import dns.immutable
import dns.rdtypes.delegbase


@dns.immutable.immutable  # pyright: ignore
class DELEGI(dns.rdtypes.delegbase.DelegBase):
    """DELEGI record"""
