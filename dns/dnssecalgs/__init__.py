import dns._features
import dns.name
from dns.dnssecalgs.base import GenericPrivateKey
from dns.dnssectypes import Algorithm
from dns.exception import UnsupportedAlgorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY

# pyright: reportPossiblyUnboundVariable=false

if dns._features.have("dnssec"):
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

    _have_cryptography = True
else:
    _have_cryptography = False

AlgorithmPrefix = bytes | dns.name.Name | None

algorithms: dict[tuple[Algorithm, AlgorithmPrefix], type[GenericPrivateKey]] = {}
if _have_cryptography:
    # pylint: disable=possibly-used-before-assignment
    algorithms.update(
        {
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
    )


def get_algorithm_cls(
    algorithm: int | str, prefix: AlgorithmPrefix = None
) -> type[GenericPrivateKey]:
    """Get Private Key class from Algorithm.

    :param algorithm: The DNSKEY algorithm.
    :type algorithm: str or int
    :raises UnsupportedAlgorithm: If the algorithm is unknown.
    :rtype: type[:py:class:`dns.dnssecalgs.base.GenericPrivateKey`]
    """
    algorithm = Algorithm.make(algorithm)
    cls = algorithms.get((algorithm, prefix))
    if cls:
        return cls
    raise UnsupportedAlgorithm(
        f'algorithm "{Algorithm.to_text(algorithm)}" not supported by dnspython'
    )


def get_algorithm_cls_from_dnskey(dnskey: DNSKEY) -> type[GenericPrivateKey]:
    """Get Private Key class from DNSKEY.

    :param dnskey: The DNSKEY rdata to get the algorithm class for.
    :type dnskey: :py:class:`dns.rdtypes.ANY.DNSKEY.DNSKEY`
    :raises UnsupportedAlgorithm: If the algorithm is unknown.
    :rtype: type[:py:class:`dns.dnssecalgs.base.GenericPrivateKey`]
    """
    prefix: AlgorithmPrefix = None
    if dnskey.algorithm == Algorithm.PRIVATEDNS:
        prefix, _ = dns.name.from_wire(dnskey.key, 0)
    elif dnskey.algorithm == Algorithm.PRIVATEOID:
        length = int(dnskey.key[0])
        prefix = dnskey.key[0 : length + 1]
    return get_algorithm_cls(dnskey.algorithm, prefix)


def register_algorithm_cls(
    algorithm: int | str,
    algorithm_cls: type[GenericPrivateKey],
    name: dns.name.Name | str | None = None,
    oid: bytes | None = None,
) -> None:
    """Register Algorithm Private Key class.

    :param algorithm: The DNSKEY algorithm.
    :type algorithm: str or int
    :param algorithm_cls: A :py:class:`dns.dnssecalgs.base.GenericPrivateKey`
        subclass.
    :param name: For PRIVATEDNS algorithms, the algorithm name.
    :type name: :py:class:`dns.name.Name`, str, or ``None``
    :param oid: For PRIVATEOID algorithms, a BER-encoded OID.
    :type oid: bytes or ``None``
    :raises ValueError: If a name or oid is specified incorrectly.
    """
    if not issubclass(algorithm_cls, GenericPrivateKey):
        raise TypeError("Invalid algorithm class")
    algorithm = Algorithm.make(algorithm)
    prefix: AlgorithmPrefix = None
    if algorithm == Algorithm.PRIVATEDNS:
        if name is None:
            raise ValueError("Name required for PRIVATEDNS algorithms")
        if isinstance(name, str):
            name = dns.name.from_text(name)
        prefix = name
    elif algorithm == Algorithm.PRIVATEOID:
        if oid is None:
            raise ValueError("OID required for PRIVATEOID algorithms")
        prefix = bytes([len(oid)]) + oid
    elif name:
        raise ValueError("Name only supported for PRIVATEDNS algorithm")
    elif oid:
        raise ValueError("OID only supported for PRIVATEOID algorithm")
    algorithms[(algorithm, prefix)] = algorithm_cls
