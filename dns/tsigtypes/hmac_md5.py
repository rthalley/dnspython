from dns.tsigtypes.hmacbase import HMACBase

import dns.name


class hmac_md5(HMACBase):
    """
    MD5 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    def __init__(self, secret):
        super(hmac_md5, self).__init__(secret)

    @classmethod
    def get_algorithm_name(cls):
        """
        Return the algorithm as a ``dns.name``
        """
        return dns.name.from_text("HMAC-MD5.SIG-ALG.REG.INT")

    @classmethod
    def get_digestmod(cls):
        return 'MD5'
