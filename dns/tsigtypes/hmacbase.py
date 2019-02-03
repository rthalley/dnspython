import hmac

from dns.tsigtypes.tsigbase import TSIGBase
from dns.exception import BadSignature


class HMACBase(TSIGBase):
    """
    Partially abstract base class for HMAC stlye algorithms.  Each child class
    is expected to define get_digestmod()
    """
    def __init__(self, secret):
        super(HMACBase, self).__init__()
        # create the appropriate digest context
        self.ctx = hmac.new(secret, digestmod=self.get_digestmod())

    @classmethod
    def get_digestmod(cls):
        """
        Static method to get the digest module for HMAC to choose the
        correct algorithm.

        Returns the ``string`` that sets the required digestmod in hmac.new()
        - e.g. "MD5", "SHA1", etc.
        """
        raise NotImplementedError

    def update(self, data):
        """
        Method to update the data that will be digested - this is effectively
        an accumulator.

        *data*, a ``binary``, is the data to be added to the accumulator to be
        digested.

        Returns nothing.
        """
        self.ctx.update(data)

    def sign(self):
        """
        Method to sign a particular set of data that is in the accumulator
        using the digest algorithm chosen.
        
        Returns a signature in ``binary``.
        """
        return self.ctx.digest()

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
        new_mac = self.ctx.digest()
        if new_mac != mac:
            raise BadSignature
        return
