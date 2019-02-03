class TSIGBase:
    """
    Abstract base class for TSIG algorithms - sub classes are expected to
    implement the various methods (no actual code here)
    """
    @classmethod
    def get_algorithm_name(cls):
        """
        Return the algorithm as a ``dns.name``
        """
        raise NotImplementedError

    def update(self, data):
        """
        Method to update the data that will be signed - this is effectively
        an accumulator.

        *data*, a ``binary``, is the data to be added to the accumulator to be
        signed.

        Returns nothing.
        """
        raise NotImplementedError

    def sign(self):
        """
        Method to sign a particular set of data that is in the accumulator
        using the algorithm chosen.

        Returns a signature in ``binary``.
        """
        raise NotImplementedError

    def verify(self, mac):
        """
        Method to verify a previously signed piece of data.

        *mac, a ``binary`` which is the signature from the message to be
        verified.

        Returns nothing; throw ``dns.exception.BadSignature`` exception on
        error.
        """
        raise NotImplementedError
