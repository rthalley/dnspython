from typing import Dict, Optional, Tuple, Type, Union

import dns.name
from dns.dnssec import UnsupportedAlgorithm
from dns.dnssecalgs.base import AlgorithmPrivateKeyBase
from dns.dnssecalgs.dsa import PrivateDSA, PrivateDSANSEC3SHA1
from dns.dnssecalgs.ecdsa import PrivateECDSAP256SHA256, PrivateECDSAP384SHA384
from dns.dnssecalgs.eddsa import PrivateED448, PrivateED25519
from dns.dnssecalgs.rsa import (PrivateRSAMD5, PrivateRSASHA1,
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
    prefix = None
    if dnskey.algorithm == Algorithm.PRIVATEDNS:
        _, length = dns.name.from_wire(dnskey.key, 0)
        prefix = dnskey.key[0:length]
    elif dnskey.algorithm == Algorithm.PRIVATEOID:
        length = int(dnskey.key[0])
        prefix = dnskey.key[0 : length + 1]
    cls = algorithms.get((dnskey.algorithm, prefix))
    if cls:
        return cls
    raise UnsupportedAlgorithm


def register_algorithm_cls(
    algorithm: Algorithm,
    algorithm_cls: Type[AlgorithmPrivateKeyBase],
    name: Optional[Union[dns.name.Name, str]] = None,
    oid: Optional[bytes] = None,
) -> None:
    """
    Register Algorithm Private Key class for an algorithm with optional
    name/oid prefix
    """
    if not issubclass(algorithm_cls, AlgorithmPrivateKeyBase):
        raise TypeError("Invalid algorithm class")
    prefix = None
    if algorithm == Algorithm.PRIVATEDNS and name:
        if isinstance(name, str):
            name = dns.name.from_text(name)
        prefix = name.to_wire()
    elif algorithm == Algorithm.PRIVATEOID and oid:
        prefix = bytes([len(oid)]) + oid
    else:
        if name:
            raise ValueError("Name only supported for PRIVATEDNS algorithm")
        if oid:
            raise ValueError("OID only supported for PRIVATEOID algorithm")
    algorithms[(algorithm, prefix)] = algorithm_cls
