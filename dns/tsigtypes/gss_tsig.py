from dns.tsigtypes.tsigbase import TSIGBase

import dns.name


class gss_tsig(TSIGBase):
    """
    GSS-TSIG TSIG implementation.  Note that as this isn't a digest-based
    algorithm, this has TSIGBase as the parent.  This uses the GSS-API context
    established in the TKEY message handshake to sign messages using GSS-API
    message integrity codes, per the RFC.

    Note there is an implicit dependency here on the Python GSSAPI package,
    although not specified, to run the get/verify signature methods.
    """
    def __init__(self, gssapi_ctx):
        super(gss_tsig, self).__init__()
        self.ctx = gssapi_ctx
        self.data = b''

    @classmethod
    def get_algorithm_name(cls):
        """
        Return the algorithm as a ``dns.name``
        """
        return dns.name.from_text("gss-tsig")

    def update(self, data):
        self.data += data

    def sign(self):
        # defer to the GSSAPI function to sign
        return self.ctx.get_signature(self.data)

    def verify(self, mac):
        # defer to the GSSAPI function to verify
        return self.ctx.verify_signature(self.data, mac)
