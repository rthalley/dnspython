import dns.immutable
import dns.rdtypes.delegbase


@dns.immutable.immutable  # pyright: ignore
class DELEG(dns.rdtypes.delegbase.DelegBase):
    """DELEG record"""
