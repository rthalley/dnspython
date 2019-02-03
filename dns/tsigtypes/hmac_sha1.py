from dns.tsigtypes.hmacbase import HMACBase

import dns.name


class hmac_sha1(HMACBase):
    """
    SHA1 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    def __init__(self, secret):
        super(hmac_sha1, self).__init__(secret)

    @classmethod
    def get_algorithm_name(cls):
        """
        Return the algorithm as a ``dns.name``
        """
        return dns.name.from_text("hmac-sha1")

    @classmethod
    def get_digestmod(cls):
        return 'SHA1'
