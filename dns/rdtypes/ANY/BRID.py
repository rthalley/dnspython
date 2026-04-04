# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import dns.immutable
import dns.rdata
import dns.rdtypes.base64base


@dns.immutable.immutable
class BRID(dns.rdtypes.base64base.Base64Base):
    """BRID record

    See RFC 9886
    """
