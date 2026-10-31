import base64
import re
from typing import NamedTuple

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, mldsa, rsa
from jwcrypto.jwk import JWK

import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zonefile
from dns.dnssec import key_id
from dns.dnssecalgs import get_algorithm_cls
from dns.dnssecalgs.base import GenericPrivateKey
from dns.dnssectypes import Algorithm


class KeyPair(NamedTuple):
    private_key: GenericPrivateKey
    dnskey_rrset: dns.rrset.RRset


class BindKeyPair(NamedTuple):
    basename: str | None
    private_data: bytes
    public_data: bytes


def _int_to_base64(value: int, length: int | None = None) -> str:
    """Convert an integer to a base64-encoded string.

    :param value: The integer to convert.
    :type value: :py:class:`int`
    :rtype: :py:class:`str`
    """
    if length is None:
        length = (value.bit_length() + 7) // 8
    return base64.b64encode(value.to_bytes(length)).decode()


def _base64_to_int(value: str) -> int:
    """Convert a base64-encoded string to an integer.

    :param value: The base64-encoded string.
    :type value: :py:class:`str`
    :rtype: :py:class:`int`
    """
    return int.from_bytes(base64.decodebytes(value.encode()))


def read_jwk_private_key(private_data: bytes) -> KeyPair:
    """Read an JWK private key from bytes and return a KeyPair.

    :param private_data: The JWK private key bytes.
    :type private_data: :py:class:`bytes`
    :rtype: :py:class:`KeyPair`
    """

    jwk = JWK.from_json(private_data.decode())

    algorithm = jwk["dnssec"]["algorithm"]
    algorithm_cls = get_algorithm_cls(algorithm)
    private_key = algorithm_cls(jwk.get_op_key("sign"))

    dnskey_rrset = dns.rrset.from_rdata(
        jwk["dnssec"]["name"],
        0,
        dns.dnssec.make_dnskey(
            public_key=private_key.public_key(),
            algorithm=jwk["dnssec"]["algorithm"],
            flags=jwk["dnssec"]["flags"],
            protocol=jwk["dnssec"]["protocol"],
        ),
    )

    return KeyPair(private_key=private_key, dnskey_rrset=dnskey_rrset)


def write_jwk_private_key(
    private_key: GenericPrivateKey,
    dnskey_rrset: dns.rrset.RRset,
) -> bytes:
    """Write private key and DNSKEY RRset and return JWK bytes.

    :param private_key: The private key to write.
    :type private_key: :py:class:`dns.dnssecalgs.base.GenericPrivateKey`
    :param dnskey_rrset: The DNSKEY RRset corresponding to the private key.
    :type dnskey_rrset: :py:class:`dns.rrset.RRset`
    :rtype: :py:class:`bytes`
    """

    if len(dnskey_rrset) != 1:
        raise ValueError("DNSKEY RRset must contain exactly one record")

    jwk = JWK.from_pyca(private_key.key)
    jwk.update(
        {
            "dnssec": {
                "name": dnskey_rrset.name.to_text(),
                "algorithm": private_key.public_key().algorithm,
                "protocol": dnskey_rrset[0].protocol,
                "flags": dnskey_rrset[0].flags,
            },
        }
    )
    return jwk.export(private_key=True).encode()


def read_bind_private_key(
    private_data: bytes,
    public_data: bytes,
) -> KeyPair:
    """Read an BIND-style private key and public key from bytes and return a KeyPair instance.

    :param private_data: The BIND-style private key bytes.
    :type private_data: :py:class:`bytes`
    :param public_data: The corresponding public DNSKEY data bytes.
    :type public_data: :py:class:`bytes`
    :rtype: :py:class:`KeyPair`
    """

    SUPPORTED_FORMATS = {"v1.3"}

    algorithm_cls: type[GenericPrivateKey] | None = None
    key_dict: dict[str, str] = {}
    dnskey_rrset: dns.rrset.RRset | None = None

    # Construct RRset from DNSKEY in public data
    rrsets = dns.zonefile.read_rrsets(public_data, rdclass=None, default_ttl=0)
    for rrset in rrsets:
        if rrset.rdtype == dns.rdatatype.DNSKEY:
            dnskey_rrset = rrset
            break

    if dnskey_rrset is None:
        raise ValueError("No DNSKEY RRset found in public data")

    for line in private_data.decode().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if match := re.match(r"^([\w\-+]+):\s*(.+)$", line):
            key_dict[match.group(1).lower()] = match.group(2)

    if key_dict.get("private-key-format") not in SUPPORTED_FORMATS:
        raise ValueError(
            f"Unsupported private key format: {key_dict.get('private-key-format')}"
        )

    algorithm = int(key_dict["algorithm"].split(" ")[0])
    algorithm_cls = get_algorithm_cls(algorithm)
    public_key = algorithm_cls.public_cls.from_dnskey(dnskey_rrset[0])

    match algorithm:
        case (
            Algorithm.RSAMD5
            | Algorithm.RSASHA1
            | Algorithm.RSASHA1NSEC3SHA1
            | Algorithm.RSASHA256
            | Algorithm.RSASHA512
        ):
            private_key_numbers = rsa.RSAPrivateNumbers(
                p=_base64_to_int(key_dict["prime1"]),
                q=_base64_to_int(key_dict["prime2"]),
                d=_base64_to_int(key_dict["privateexponent"]),
                dmp1=_base64_to_int(key_dict["exponent1"]),
                dmq1=_base64_to_int(key_dict["exponent2"]),
                iqmp=_base64_to_int(key_dict["coefficient"]),
                public_numbers=rsa.RSAPublicNumbers(
                    e=_base64_to_int(key_dict["publicexponent"]),
                    n=_base64_to_int(key_dict["modulus"]),
                ),
            )
            private_key = private_key_numbers.private_key()

        case Algorithm.ECDSAP256SHA256 | Algorithm.ECDSAP384SHA384:
            private_bytes = base64.decodebytes(key_dict["privatekey"].encode())
            private_key_numbers = ec.EllipticCurvePrivateNumbers(
                private_value=int.from_bytes(private_bytes, "big"),
                public_numbers=public_key.key.public_numbers(),
            )
            private_key = private_key_numbers.private_key()

        case Algorithm.ED25519:
            private_bytes = base64.decodebytes(key_dict["privatekey"].encode())
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)

        case Algorithm.ED448:
            private_bytes = base64.decodebytes(key_dict["privatekey"].encode())
            private_key = ed448.Ed448PrivateKey.from_private_bytes(private_bytes)

        case Algorithm.MLDSA44:
            seed_bytes = base64.decodebytes(key_dict["privatekey"].encode())
            private_key = mldsa.MLDSA44PrivateKey.from_seed_bytes(seed_bytes)

        case _:
            raise NotImplementedError(f"Algorithm {algorithm} not supported")

    return KeyPair(private_key=algorithm_cls(private_key), dnskey_rrset=dnskey_rrset)


def write_bind_private_key(
    private_key: GenericPrivateKey,
    dnskey_rrset: dns.rrset.RRset,
) -> BindKeyPair:
    """Write private key and DNSKEY RRset to BIND-style bytes.

    :param private_key: The private key to write.
    :type private_key: :py:class:`dns.dnssecalgs.base.GenericPrivateKey`
    :param dnskey_rrset: The DNSKEY RRset corresponding to the private key.
    :type dnskey_rrset: :py:class:`dns.rrset.RRset`
    :rtype: :py:class:`BindKeyPair`
    """

    if len(dnskey_rrset) != 1:
        raise ValueError("DNSKEY RRset must contain exactly one record")

    public_data = dnskey_rrset.to_text(
        style=dns.rdataset.RdatasetStyle(omit_ttl=True)
    ).encode()
    private_data = {}
    basename = f"K{dnskey_rrset.name.to_text()}+{private_key.public_cls.algorithm.value:03}+{key_id(dnskey_rrset[0]):05}"

    private_data["Private-key-format"] = "v1.3"
    private_data["Algorithm"] = (
        f"{private_key.public_cls.algorithm.value} ({private_key.public_cls.algorithm.name})"
    )

    algorithm = private_key.public_cls.algorithm

    match algorithm:
        case (
            Algorithm.RSAMD5
            | Algorithm.RSASHA1
            | Algorithm.RSASHA1NSEC3SHA1
            | Algorithm.RSASHA256
            | Algorithm.RSASHA512
        ):
            private_key_numbers = private_key.key.private_numbers()
            private_data.update(
                {
                    "Modulus": _int_to_base64(private_key_numbers.public_numbers.n),
                    "PublicExponent": _int_to_base64(
                        private_key_numbers.public_numbers.e
                    ),
                    "PrivateExponent": _int_to_base64(private_key_numbers.d),
                    "Prime1": _int_to_base64(private_key_numbers.p),
                    "Prime2": _int_to_base64(private_key_numbers.q),
                    "Exponent1": _int_to_base64(private_key_numbers.dmp1),
                    "Exponent2": _int_to_base64(private_key_numbers.dmq1),
                    "Coefficient": _int_to_base64(private_key_numbers.iqmp),
                }
            )

        case Algorithm.ECDSAP256SHA256 | Algorithm.ECDSAP384SHA384:
            private_key_numbers = private_key.key.private_numbers()
            curve_size = private_key_numbers.public_numbers.curve.key_size // 8
            private_data.update(
                {
                    "PrivateKey": _int_to_base64(
                        private_key_numbers.private_value, curve_size
                    )
                }
            )

        case Algorithm.ED25519 | Algorithm.ED448 | Algorithm.MLDSA44:
            private_data.update(
                {
                    "PrivateKey": base64.encodebytes(
                        private_key.key.private_bytes_raw()
                    ).decode()
                }
            )

        case _:
            raise NotImplementedError(f"Algorithm {algorithm} not supported")

    return BindKeyPair(
        basename=basename,
        private_data=b"\n".join(
            f"{key}: {value}".encode() for key, value in private_data.items()
        ),
        public_data=public_data,
    )
