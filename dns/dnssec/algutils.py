from typing import Dict, Optional, Tuple, Type

from dns.dnssec import UnsupportedAlgorithm
from dns.dnssec.algbase import AlgorithmPrivateKeyBase
from dns.dnssec.dsa import PrivateDSA, PrivateDSANSEC3SHA1
from dns.dnssec.ecdsa import PrivateECDSAP256SHA256, PrivateECDSAP384SHA384
from dns.dnssec.eddsa import PrivateED448, PrivateED25519
from dns.dnssec.rsa import (PrivateRSAMD5, PrivateRSASHA1,
                            PrivateRSASHA1NSEC3SHA1, PrivateRSASHA256,
                            PrivateRSASHA512)
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY

algorithms: Dict[Tuple[Algorithm, Optional[bytes]], Type[AlgorithmPrivateKeyBase]] = {
    (Algorithm.RSAMD5, None): PrivateRSAMD5,
    (Algorithm.DSA, None): PrivateDSA,
    (Algorithm.RSASHA1, None): PrivateRSASHA1,
    (Algorithm.DSANSEC3SHA1, None): PrivateDSANSEC3SHA1,
    (Algorithm.RSASHA1NSEC3SHA1, None): PrivateRSASHA1NSEC3SHA1,
    (Algorithm.RSASHA256, None): PrivateRSASHA256,
    (Algorithm.RSASHA512, None): PrivateRSASHA512,
    (Algorithm.ECDSAP256SHA256, None): PrivateECDSAP256SHA256,
    (Algorithm.ECDSAP384SHA384, None): PrivateECDSAP384SHA384,
    (Algorithm.ED25519, None): PrivateED25519,
    (Algorithm.ED448, None): PrivateED448,
}


def _is_private(algorithm: Algorithm) -> bool:
    return algorithm in set([Algorithm.PRIVATEDNS, Algorithm.PRIVATEOID])


def get_algorithm_cls(dnskey: DNSKEY) -> Type[AlgorithmPrivateKeyBase]:
    """Get Algorithm Private Key class from DNSKEY"""
    cls = algorithms.get((dnskey.algorithm, None))
    if cls:
        return cls
    if _is_private(dnskey.algorithm):
        for k, cls in algorithms.items():
            algorithm, prefix = k
            if algorithm != dnskey.algorithm:
                continue
            if prefix is None or dnskey.key.startswith(prefix):
                return cls
    raise UnsupportedAlgorithm


def register_algorithm_cls(
    algorithm: Algorithm,
    algorithm_cls: Type[AlgorithmPrivateKeyBase],
    prefix: Optional[bytes] = None,
) -> None:
    """Register Algorithm Private Key class for an algorithm with optional prefix"""
    if not issubclass(algorithm_cls, AlgorithmPrivateKeyBase):
        raise TypeError("Invalid algorithm class")
    if prefix and not _is_private(algorithm):
        raise ValueError("Prefix only supported for private algorithms")
    algorithms[(algorithm, prefix)] = algorithm_cls
