import base64
import binascii
import dataclasses
import json
import os
import re
from pathlib import Path
from typing import Self

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, mldsa, rsa
from jwcrypto.common import JWException
from jwcrypto.jwk import JWK

import dns.dnssec
import dns.dnssectypes
import dns.name
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rrset
import dns.zonefile
from dns.dnssec import key_id
from dns.dnssecalgs import get_algorithm_cls
from dns.dnssecalgs.base import GenericPrivateKey, GenericPublicKey
from dns.dnssecalgs.cryptography import CryptographyPrivateKey, CryptographyPublicKey
from dns.dnssectypes import Algorithm, DSDigest
from dns.exception import DNSException, InvalidKeyFormat

SUPPORTED_BIND_PRIVATE_KEY_FORMATS = {"v1.3"}


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
    return int.from_bytes(base64.b64decode(value.encode(), validate=True))


@dataclasses.dataclass(frozen=True)
class Key:
    """Represents a DNSSEC key with associated public and private keys."""

    name: dns.name.Name
    public: GenericPublicKey
    private: GenericPrivateKey | None
    dnskey: dns.rdtypes.ANY.DNSKEY.DNSKEY

    def to_ds(self, algorithm: DSDigest | str = "SHA256") -> dns.rdtypes.ANY.DS.DS:
        """Return the DS record for the key.

        :param algorithm: The hash algorithm. Currently supported: ``"SHA1"``,
            ``"SHA256"``, ``"SHA384"`` (case-insensitive).
        :type algorithm: :py:class:`DSDigest` or :py:class:`str`
        :rtype: :py:class:`dns.rdtypes.ANY.DS.DS`
        """

        return dns.dnssec.make_ds(self.name, self.dnskey, algorithm)

    def key_id(self) -> int:
        """Return the key ID for the key.

        :rtype: :py:class:`int`
        """
        return key_id(self.dnskey)

    @classmethod
    def from_jwk(cls, data: bytes) -> Self:
        """Create key from JWK bytes.

        :param data: The JWK key bytes.
        :type data: :py:class:`bytes`
        :rtype: :py:class:`Key`
        """

        try:
            jwk = JWK.from_json(data.decode())

            dnssec_properties = jwk["dnssec"]

            algorithm = dnssec_properties["algorithm"]
            algorithm_cls = get_algorithm_cls(algorithm)

            if jwk.has_private:
                private_key = algorithm_cls(jwk.get_op_key("sign"))
                public_key = private_key.public_key()
            else:
                private_key = None
                public_key = algorithm_cls.public_cls(jwk.get_op_key("verify"))

            name = dns.name.from_text(dnssec_properties["name"])

            keytag = dnssec_properties["keytag"]

            dnskey = dns.dnssec.make_dnskey(
                public_key=public_key,
                algorithm=dnssec_properties["algorithm"],
                flags=dnssec_properties["flags"],
                protocol=dnssec_properties["protocol"],
            )
        except (KeyError, ValueError, TypeError, binascii.Error, JWException) as exc:
            raise InvalidKeyFormat("Failed to create key from JWK") from exc

        if keytag != key_id(dnskey):
            raise InvalidKeyFormat("Keytag mismatch between JWK and DNSKEY")

        return cls(
            name=name,
            private=private_key,
            public=public_key,
            dnskey=dnskey,
        )

    def to_jwk(self, public_only: bool = False) -> bytes:
        """Return JWK bytes for the key.

        DNSKEY information will be included in the JWK under the "dnssec" key
        and includes name, algorithm, protocol, flags, and keytag.

        :param public_only: Whether to include only the public key in the JWK.
        :type public_only: :py:class:`bool`
        :rtype: :py:class:`bytes`
        """

        if public_only:
            if isinstance(self.public, CryptographyPublicKey):
                jwk = JWK.from_pyca(self.public.key)
            else:
                raise InvalidKeyFormat("Unsupported public key type")
        else:
            if isinstance(self.private, CryptographyPrivateKey):
                jwk = JWK.from_pyca(self.private.key)
            elif self.private is None:
                raise InvalidKeyFormat("Private key is not set")
            else:
                raise InvalidKeyFormat("Unsupported private key type")

        jwk_dict = jwk.export(private_key=not public_only, as_dict=True)

        jwk_dict.update(
            {
                "dnssec": {
                    "name": self.name.to_text(),
                    "algorithm": self.dnskey.algorithm,
                    "protocol": self.dnskey.protocol,
                    "flags": self.dnskey.flags,
                    "keytag": key_id(self.dnskey),
                },
            }
        )

        return json.dumps(jwk_dict).encode()

    @classmethod
    def from_bind(cls, private_filename: Path | str) -> Self:
        """Read the key from BIND-style files.

        :param private_filename: The path to the input file. Must follow the BIND-style naming convention.
        :type private_filename: :py:class:`Path` or :py:class:`str`
        :rtype: :py:class:`Key`
        """

        if isinstance(private_filename, str):
            private_filename = Path(private_filename)

        public_filename = private_filename.with_suffix(".key")

        if match := re.fullmatch(r"K.*\+.*\+(\d{5})\.private", private_filename.name):
            expected_key_id = int(match.group(1))
        else:
            raise InvalidKeyFormat(
                f"Invalid private key filename: {private_filename.name}"
            )

        with open(private_filename, "rb") as fp:
            private_data = fp.read()

        with open(public_filename, "rb") as fp:
            public_data = fp.read()

        try:
            res = cls._from_bind_data(
                private_data=private_data, public_data=public_data
            )
        except (KeyError, ValueError, SyntaxError, TypeError, binascii.Error) as exc:
            raise InvalidKeyFormat("Failed to create key from BIND keys") from exc

        if not expected_key_id == res.key_id():
            raise InvalidKeyFormat(
                f"Key ID mismatch: expected {expected_key_id}, got {res.key_id()}"
            )

        return res

    @classmethod
    def _from_bind_data(cls, private_data: bytes, public_data: bytes) -> Self:
        """Create a key pair from BIND-style key data.

        :param private_data: The private key data.
        :type private_data: :py:class:`bytes`
        :param public_data: The public key data.
        :type public_data: :py:class:`bytes`
        :rtype: :py:class:`Key`
        """

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
            raise InvalidKeyFormat("No DNSKEY RRset found in public data")

        if len(dnskey_rrset) != 1:
            raise InvalidKeyFormat("DNSKEY RRset must contain exactly one record")

        dnskey_rdata = dnskey_rrset[0]
        if not isinstance(dnskey_rdata, dns.rdtypes.ANY.DNSKEY.DNSKEY):
            raise InvalidKeyFormat("RRset does not contain a valid DNSKEY record")

        for line in private_data.decode().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if match := re.match(r"^([\w\-+]+):\s*(.+)$", line):
                key_dict[match.group(1).lower()] = match.group(2)

        if key_dict.get("private-key-format") not in SUPPORTED_BIND_PRIVATE_KEY_FORMATS:
            raise InvalidKeyFormat(
                f"Unsupported private key format: {key_dict.get('private-key-format')}"
            )

        algorithm = int(key_dict["algorithm"].split(" ")[0])

        if algorithm != dnskey_rdata.algorithm:
            raise InvalidKeyFormat(
                f"Algorithm mismatch between private key ({algorithm}) and DNSKEY ({dnskey_rdata.algorithm})"
            )

        algorithm_cls = get_algorithm_cls(algorithm)
        public_key = algorithm_cls.public_cls.from_dnskey(dnskey_rdata)

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
                if not isinstance(public_key, CryptographyPublicKey):
                    raise TypeError(
                        "Public key is not a valid CryptographyPublicKey instance"
                    )
                private_bytes = base64.b64decode(
                    key_dict["privatekey"].encode(), validate=True
                )
                private_key_numbers = ec.EllipticCurvePrivateNumbers(
                    private_value=int.from_bytes(private_bytes, "big"),
                    public_numbers=public_key.key.public_numbers(),
                )
                private_key = private_key_numbers.private_key()

            case Algorithm.ED25519:
                private_bytes = base64.b64decode(
                    key_dict["privatekey"].encode(), validate=True
                )
                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(
                    private_bytes
                )

            case Algorithm.ED448:
                private_bytes = base64.b64decode(
                    key_dict["privatekey"].encode(), validate=True
                )
                private_key = ed448.Ed448PrivateKey.from_private_bytes(private_bytes)

            case Algorithm.MLDSA44:
                seed_bytes = base64.b64decode(
                    key_dict["privatekey"].encode(), validate=True
                )
                private_key = mldsa.MLDSA44PrivateKey.from_seed_bytes(seed_bytes)

            case _:
                raise NotImplementedError(
                    f"Algorithm {algorithm} not implemented when importing private key"
                )

        private = algorithm_cls(private_key)
        public = private.public_key()

        if public.to_dnskey().key != dnskey_rdata.key:
            raise InvalidKeyFormat("Private key does not match DNSKEY")

        return cls(
            name=dnskey_rrset.name,
            private=private,
            public=public,
            dnskey=dnskey_rdata,
        )

    def to_bind(self, directory: Path | str, overwrite: bool = False) -> Path:
        """Write the key to BIND-style files.

        :param directory: The path to the output directory.
        :type directory: :py:class:`Path`
        :param overwrite: Whether to overwrite existing key files.
        :type overwrite: bool
        :rtype: Path
        """

        if isinstance(directory, str):
            directory = Path(directory)

        if not (directory.exists() and directory.is_dir()):
            raise NotADirectoryError(f"{directory} is not a valid directory")

        public_data = self._to_bind_public()
        private_data = self._to_bind_private()

        basename = f"K{self.name.to_text()}+{self.dnskey.algorithm.value:03}+{self.key_id():05}"

        private_filename = directory / f"{basename}.private"
        public_filename = directory / f"{basename}.key"

        if overwrite:
            # If overwrite is True, remove existing files before writing
            public_filename.unlink(missing_ok=True)
            private_filename.unlink(missing_ok=True)
        else:
            # Abort if the key files already exist to prevent overwriting existing keys
            if private_filename.exists():
                raise FileExistsError(
                    f"Private key file {private_filename} already exists"
                )
            if public_filename.exists():
                raise FileExistsError(
                    f"Public key file {public_filename} already exists"
                )

        try:
            with open(public_filename, "xb") as fp:
                fp.write(public_data)

            with open(
                os.open(
                    private_filename,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                ),
                "wb",
            ) as fp:
                fp.write(private_data)
        except Exception:
            # Remove any partially written key files to avoid leaving incomplete files on disk
            public_filename.unlink(missing_ok=True)
            private_filename.unlink(missing_ok=True)
            raise

        return private_filename

    def _to_bind_public(self) -> bytes:
        """Return the public key in BIND-style format."""
        rrset = dns.rrset.from_rdata(self.name, 0, self.dnskey)
        return rrset.to_text(style=dns.rdataset.RdatasetStyle(omit_ttl=True)).encode()

    def _to_bind_private(self) -> bytes:
        """Return the private key in BIND-style format."""

        if self.private is None:
            raise DNSException("Private key is not set")

        if not isinstance(self.private, CryptographyPrivateKey):
            raise TypeError(
                "Private key is not a valid CryptographyPrivateKey instance"
            )

        private_data_dict = {
            "Private-key-format": "v1.3",
            "Algorithm": f"{self.dnskey.algorithm.value} ({self.dnskey.algorithm.name})",
        }

        match self.dnskey.algorithm:
            case (
                Algorithm.RSAMD5
                | Algorithm.RSASHA1
                | Algorithm.RSASHA1NSEC3SHA1
                | Algorithm.RSASHA256
                | Algorithm.RSASHA512
            ):
                private_key_numbers = self.private.key.private_numbers()
                private_data_dict.update(
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
                private_key_numbers = self.private.key.private_numbers()
                curve_size = private_key_numbers.public_numbers.curve.key_size // 8
                private_data_dict.update(
                    {
                        "PrivateKey": _int_to_base64(
                            private_key_numbers.private_value, curve_size
                        )
                    }
                )

            case Algorithm.ED25519 | Algorithm.ED448 | Algorithm.MLDSA44:
                private_data_dict.update(
                    {
                        "PrivateKey": base64.b64encode(
                            self.private.key.private_bytes_raw()
                        ).decode()
                    }
                )

            case _:
                raise NotImplementedError(
                    f"Algorithm {self.dnskey.algorithm} not implemented when exporting private key"
                )

        return (
            b"\n".join(
                f"{key}: {value}".encode() for key, value in private_data_dict.items()
            )
            + b"\n"
        )
