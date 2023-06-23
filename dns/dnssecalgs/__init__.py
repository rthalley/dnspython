from typing import Dict, Optional, Tuple, Type, Union

import dns.name
from dns.dnssecalgs.base import GenericPrivateKey
from dns.dnssecalgs.dsa import PrivateDSA, PrivateDSANSEC3SHA1
from dns.dnssecalgs.ecdsa import PrivateECDSAP256SHA256, PrivateECDSAP384SHA384
from dns.dnssecalgs.eddsa import PrivateED448, PrivateED25519
from dns.dnssecalgs.rsa import (
    PrivateRSAMD5,
    PrivateRSASHA1,
    PrivateRSASHA1NSEC3SHA1,
    PrivateRSASHA256,
    PrivateRSASHA512,
)
from dns.dnssectypes import Algorithm
from dns.exception import UnsupportedAlgorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


AlgorithmPrefix = Optional[Union[bytes, dns.name.Name]]

algorithms: Dict[Tuple[Algorithm, AlgorithmPrefix], Type[GenericPrivateKey]] = {
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


def get_algorithm_cls(
    algorithm: Union[int, str], prefix: AlgorithmPrefix = None
) -> Type[GenericPrivateKey]:
    """Get Private Key class from Algorithm.

    *algorithm*, a ``str`` or ``int`` specifying the DNSKEY algorithm.

    Raises ``UnsupportedAlgorithm`` if the algorithm is unknown.

    Returns a ``dns.dnssecalgs.GenericPrivateKey``
    """
    algorithm = Algorithm.make(algorithm)
    if prefix:
        cls = algorithms.get((algorithm, prefix))
        if cls:
            return cls
    cls = algorithms.get((algorithm, None))
    if cls:
        return cls
    raise UnsupportedAlgorithm(
        'algorithm "%s" not supported by dnspython' % Algorithm.to_text(algorithm)
    )


def get_algorithm_cls_from_dnskey(dnskey: DNSKEY) -> Type[GenericPrivateKey]:
    """Get Private Key class from DNSKEY.

    *dnskey*, a ``DNSKEY`` to get Algorithm class for.

    Raises ``UnsupportedAlgorithm`` if the algorithm is unknown.

    Returns a ``dns.dnssecalgs.GenericPrivateKey``
    """
    prefix: AlgorithmPrefix = None
    if dnskey.algorithm == Algorithm.PRIVATEDNS:
        prefix, _ = dns.name.from_wire(dnskey.key, 0)
    elif dnskey.algorithm == Algorithm.PRIVATEOID:
        length = int(dnskey.key[0])
        prefix = dnskey.key[0 : length + 1]
    return get_algorithm_cls(dnskey.algorithm, prefix)


def register_algorithm_cls(
    algorithm: Union[int, str],
    algorithm_cls: Type[GenericPrivateKey],
    name: Optional[Union[dns.name.Name, str]] = None,
    oid: Optional[bytes] = None,
) -> None:
    """Register Algorithm Private Key class.

    *algorithm*, a ``str`` or ``int`` specifying the DNSKEY algorithm.

    *algorithm_cls*: A `GenericPrivateKey` class.

    *name*, an optional ``dns.name.Name`` or ``str``, for for PRIVATEDNS algorithms.

    *oid*: an optional BER-encoded `bytes` for PRIVATEOID algorithms.

    Raises ``ValueError`` if a name or oid is specified incorrectly.
    """
    if not issubclass(algorithm_cls, GenericPrivateKey):
        raise TypeError("Invalid algorithm class")
    algorithm = Algorithm.make(algorithm)
    prefix: AlgorithmPrefix = None
    if algorithm == Algorithm.PRIVATEDNS and name:
        if isinstance(name, str):
            name = dns.name.from_text(name)
        prefix = name
    elif algorithm == Algorithm.PRIVATEOID and oid:
        prefix = bytes([len(oid)]) + oid
    else:
        if name and algorithm != Algorithm.PRIVATEDNS:
            raise ValueError("Name only supported for PRIVATEDNS algorithm")
        if oid and algorithm != Algorithm.PRIVATEOID:
            raise ValueError("OID only supported for PRIVATEOID algorithm")
    algorithms[(algorithm, prefix)] = algorithm_cls
