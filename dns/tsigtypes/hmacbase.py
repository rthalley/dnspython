import hmac

import dns.name
from dns.tsigtypes.tsigbase import TSIGBase, TSIGContext
from dns.tsig import BadSignature


class HMACBase(TSIGBase):
    """
    Base class for HMAC style algorithms.  Each child class calls the
    constructor with the right strings to map the digest module and algorithm.
    """
    def __init__(self, secret):
        _type = type(self).algorithm_type()
        super().__init__(
            TSIGContext(_type, hmac.new(secret, digestmod=_type))
        )

    def update(self, data):
        """
        Method to update the data that will be digested - this is effectively
        an accumulator.

        *data*, a ``binary``, is the data to be added to the accumulator to be
        digested.

        Returns nothing.
        """
        self.ctx.data.update(data)

    def sign(self):
        """
        Method to sign a particular set of data that is in the accumulator
        using the digest algorithm chosen.

        Returns a signature in ``binary``.
        """
        return self.ctx.data.digest()

    def verify(self, mac):
        """
        Method to verify a previously signed piece of data.  In the case
        of HMAC style algorithms, this is just a case of signing the same
        dataset from the DNS message and comparing the signatures.

        *mac, a ``binary`` which is the signature from the message to be
        verified.

        Returns nothing; throw ``dns.exception.BadSignature`` exception on
        error.
        """
        new_mac = self.ctx.data.digest()
        if new_mac != mac:
            raise BadSignature
        return
