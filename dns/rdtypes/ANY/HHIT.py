# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import dns.immutable
import dns.rdata
import dns.rdtypes.base64base


@dns.immutable.immutable
class HHIT(dns.rdtypes.base64base.Base64Base):
    """HHIT record

    See RFC 9886
    """
