import dns.rdatatype
from dns.rdtypes.ANY.TLSA import TLSA


@dns.immutable.immutable
class SMIMEA(TLSA):
    """SMIMEA record, same format as TLSA per https://tools.ietf.org/html/rfc8162#section-2"""
