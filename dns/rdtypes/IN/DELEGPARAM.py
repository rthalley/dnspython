# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import dns.immutable
import dns.rdtypes.delegbase


@dns.immutable.immutable  # pyright: ignore
class DELEGPARAM(dns.rdtypes.delegbase.DelegBase):
    """DELEGPARAM record"""
