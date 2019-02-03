import dns.name


class TSIGContext:
    """
    Class containing TSIG context for TSIG algorithm being used
    """
    def __init__(self, impl, data):
        self._impl = impl
        self._data = data

    @property
    def impl(self):
        return self._impl

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, _data):
        self._data = _data


class TSIGBase:
    """
    Abstract base class for TSIG algorithms - sub classes are expected to
    implement the various methods (no actual code here)
    """
    def __init__(self, ctx):
        self._ctx = ctx

    @classmethod
    def algorithm_name(cls):
        """
        Get the algorithm name for the TSIG.

        Returns name of algorithm in ``dns.name`` format.
        """
        return dns.name.from_text(cls._algorithm_name)

    @classmethod
    def algorithm_type(cls):
        """
        Get the algorithm type for the TSIG - note, only applies to HMAC types.

        Returns type of algorithm.
        """
        return cls._algorithm_type

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

    @property
    def ctx(self):
        return self._ctx
