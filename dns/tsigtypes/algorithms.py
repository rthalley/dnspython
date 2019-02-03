import hashlib

from dns.tsigtypes.tsigbase import TSIGBase, TSIGContext
from dns.tsigtypes.hmacbase import HMACBase


class hmac_md5(HMACBase):
    """
    MD5 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    _algorithm_name = "HMAC-MD5.SIG-ALG.REG.INT"
    _algorithm_type = hashlib.md5


class hmac_sha1(HMACBase):
    """
    SHA1 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    _algorithm_name = "hmac-sha1"
    _algorithm_type = hashlib.sha1


class hmac_sha224(HMACBase):
    """
    SHA224 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    _algorithm_name = "hmac-sha224"
    _algorithm_type = hashlib.sha224


class hmac_sha256(HMACBase):
    """
    SHA256 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    _algorithm_name = "hmac-sha256"
    _algorithm_type = hashlib.sha256


class hmac_sha384(HMACBase):
    """
    SHA384 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    _algorithm_name = "hmac-sha384"
    _algorithm_type = hashlib.sha384


class hmac_sha512(HMACBase):
    """
    SHA512 HMAC Algorithm.  See :ref:`HMACBase` for the remaining documentation.
    """
    _algorithm_name = "hmac-sha512"
    _algorithm_type = hashlib.sha512


class gss_tsig(TSIGBase):
    """
    GSS-TSIG TSIG implementation.  Note that as this isn't a digest-based
    algorithm, this has TSIGBase as the parent.  This uses the GSS-API context
    established in the TKEY message handshake to sign messages using GSS-API
    message integrity codes, per the RFC.

    Note there is an implicit dependency here on the Python GSSAPI package,
    although not specified, to run the get/verify signature methods.
    """
    _algorithm_name = "gss-tsig"
    _algorithm_type = None

    def __init__(self, gssapi):
        super().__init__(TSIGContext(gssapi, b''))

    def update(self, data):
        self.ctx.data += data

    def sign(self):
        # defer to the GSSAPI function to sign
        return self.ctx.impl.get_signature(self.ctx.data)

    def verify(self, mac):
        # defer to the GSSAPI function to verify
        return self.ctx.impl.verify_signature(self.ctx.data, mac)
