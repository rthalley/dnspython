from dns.tsigtypes.hmacbase import HMACBase

import dns.name


class hmac_sha224(HMACBase):
    """
    SHA224 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    def __init__(self, secret):
        super(hmac_sha224, self).__init__(secret)

    @classmethod
    def get_algorithm_name(cls):
        """
        Return the algorithm as a ``dns.name``
        """
        return dns.name.from_text("hmac-sha224")

    @classmethod
    def get_digestmod(cls):
        return 'SHA224'
