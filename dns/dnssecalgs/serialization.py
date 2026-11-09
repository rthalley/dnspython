import base64
import binascii
import dataclasses
import json
import os
import re
import tempfile
import urllib.parse
from pathlib import Path
from typing import BinaryIO, Self, TextIO

from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, mldsa, rsa

import dns._features
import dns._file_util
import dns.dnssec
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
from dns.exception import DNSException, InvalidKeyFormat, SyntaxError

if dns._features.have("jwk"):
    from jwcrypto.common import JWException
    from jwcrypto.jwk import JWK


SUPPORTED_BIND_PRIVATE_KEY_FORMATS = {"v1.3"}
DNSKEY_JWK_PARAMETER = "dnskey"


class NoJWK(DNSException):
    """JSON Web Keys not available; install jwcrypto."""


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


def _encode_name(name: dns.name.Name) -> str:
    """Encode a DNS name for use in BIND-style filenames.

    :param name: The DNS name to encode.
    :type name: :py:class:`dns.name.Name`
    :rtype: :py:class:`str`
    """

    if name == dns.name.root:
        return "."
    return ".".join(
        "".join(
            (
                chr(b).lower()
                if chr(b).isascii() and (chr(b).isalnum() or chr(b) in "-_")
                else f"%{b:02X}"
            )
            for b in label
        )
        for label in name.labels
    )


def _decode_name(encoded_name: str) -> dns.name.Name:
    """Decode a BIND-style filename into a DNS name.

    :param encoded_name: The encoded DNS name from the filename.
    :type encoded_name: :py:class:`str`
    :rtype: :py:class:`dns.name.Name`
    """

    if encoded_name == ".":
        return dns.name.root

    try:
        labels = [
            urllib.parse.unquote_to_bytes(l) for l in encoded_name[:-1].split(".")
        ]
        return dns.name.Name(labels + [b""])
    except (ValueError, dns.exception.DNSException) as exc:
        raise InvalidKeyFormat(f"Invalid name in filename: {encoded_name}") from exc


@dataclasses.dataclass(frozen=True)
class Key:
    """Represents a DNSSEC key with associated public and private keys."""

    name: dns.name.Name
    public: GenericPublicKey
    private: GenericPrivateKey | None
    dnskey: dns.rdtypes.ANY.DNSKEY.DNSKEY

    def __post_init__(self) -> None:
        """Validate the types of the key components."""
        if not isinstance(self.name, dns.name.Name):
            raise TypeError("name must be a dns.name.Name instance")
        if self.name.is_absolute() is False:
            raise ValueError("name must be an absolute DNS name")
        if not isinstance(self.public, GenericPublicKey):
            raise TypeError("public must be a GenericPublicKey instance")
        if self.private is not None and not isinstance(self.private, GenericPrivateKey):
            raise TypeError("private must be a GenericPrivateKey instance or None")
        if not isinstance(self.dnskey, dns.rdtypes.ANY.DNSKEY.DNSKEY):
            raise TypeError("dnskey must be a dns.rdtypes.ANY.DNSKEY.DNSKEY instance")

    def to_ds(self, algorithm: DSDigest | str) -> dns.rdtypes.ANY.DS.DS:
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
    def from_dnskey(
        cls, name: dns.name.Name | str, dnskey: dns.rdtypes.ANY.DNSKEY.DNSKEY
    ) -> Self:
        """Create key from a DNSKEY record.

        :param name: The DNS name associated with the key.
        :type name: :py:class:`dns.name.Name` or :py:class:`str`
        :param dnskey: The DNSKEY record.
        :type dnskey: :py:class:`dns.rdtypes.ANY.DNSKEY.DNSKEY`
        :rtype: :py:class:`Key`
        """

        if isinstance(name, str):
            name = dns.name.from_text(name)

        public_key = get_algorithm_cls(dnskey.algorithm).public_cls.from_dnskey(dnskey)
        return cls(
            name=name,
            private=None,
            public=public_key,
            dnskey=dnskey,
        )

    @classmethod
    def from_jwk_file(cls, f: str | os.PathLike | TextIO | BinaryIO) -> Self:
        """Create key from a JWK file.

        :param f: The path to the JWK file or a file-like object.
        :type f: :py:class:`str`, :py:class:`os.PathLike`, :py:class:`TextIO`,
            or :py:class:`BinaryIO`
        :rtype: :py:class:`Key`
        """

        if not dns._features.have("jwk"):
            raise NoJWK
        with dns._file_util.maybe_open(f, encoding="utf-8") as fp:
            data = fp.read()
        return cls.from_jwk_text(data)

    @classmethod
    def from_jwk_text(cls, data: str) -> Self:
        """Create key from JWK text.

        :param data: The JWK key text.
        :type data: :py:class:`str`
        :rtype: :py:class:`Key`
        """

        if not dns._features.have("jwk"):
            raise NoJWK
        try:
            jwk = JWK.from_json(data)  # pyright: ignore

            dnskey_properties = jwk[DNSKEY_JWK_PARAMETER]
            algorithm = dnskey_properties["algorithm"]
            algorithm = dnskey_properties["algorithm"]
            algorithm_cls = get_algorithm_cls(algorithm)

            if jwk.has_private:
                private_key = algorithm_cls(jwk.get_op_key("sign"))
                public_key = private_key.public_key()
            else:
                private_key = None
                public_key = algorithm_cls.public_cls(jwk.get_op_key("verify"))

            name = dns.name.from_text(dnskey_properties["name"])

            keytag = dnskey_properties["keytag"]

            dnskey = dns.dnssec.make_dnskey(
                public_key=public_key,
                algorithm=dnskey_properties["algorithm"],
                flags=dnskey_properties["flags"],
                protocol=dnskey_properties["protocol"],
            )
        except (
            KeyError,
            ValueError,
            TypeError,
            binascii.Error,
            JWException,  # pyright: ignore
        ) as exc:
            raise InvalidKeyFormat("Failed to create key from JWK") from exc

        if keytag != key_id(dnskey):
            raise InvalidKeyFormat("Keytag mismatch between JWK and DNSKEY")

        return cls(
            name=name,
            private=private_key,
            public=public_key,
            dnskey=dnskey,
        )

    def to_jwk_file(
        self, f: str | os.PathLike | BinaryIO | TextIO, public_only: bool = False
    ) -> None:
        """Write the key to a JWK file.

        :param f: The path to the output file or a file-like object.
        :type f: :py:class:`str`, :py:class:`os.PathLike`, :py:class:`BinaryIO`,
            or :py:class:`TextIO`
        :param public_only: Whether to include only the public key in the JWK.
        :type public_only: :py:class:`bool`
        """

        if not dns._features.have("jwk"):
            raise NoJWK
        with dns._file_util.maybe_open(
            f, "wb", chmod=None if public_only else 0o600
        ) as output:
            jwk_str = self.to_jwk_text(public_only=public_only)
            try:
                output.write(jwk_str.encode())
            except TypeError:
                output.write(jwk_str)

    def to_jwk_text(self, public_only: bool = False) -> str:
        """Return JWK string for the key.

        DNSKEY information will be included in the JWK in the "dnskey" parameter
        and includes name, algorithm, protocol, flags, and keytag.

        :param public_only: Whether to include only the public key in the JWK.
        :type public_only: :py:class:`bool`
        :rtype: :py:class:`str`
        """

        if not dns._features.have("jwk"):
            raise NoJWK
        if public_only:
            if isinstance(self.public, CryptographyPublicKey):
                jwk = JWK.from_pyca(self.public.key)  # pyright: ignore
            else:
                raise InvalidKeyFormat("Unsupported public key type")
        else:
            if isinstance(self.private, CryptographyPrivateKey):
                jwk = JWK.from_pyca(self.private.key)  # pyright: ignore
            elif self.private is None:
                raise InvalidKeyFormat("Private key is not set")
            else:
                raise InvalidKeyFormat("Unsupported private key type")

        jwk_dict = jwk.export(private_key=not public_only, as_dict=True)

        jwk_dict.update(
            {
                DNSKEY_JWK_PARAMETER: {
                    "name": self.name.to_text(),
                    "algorithm": self.dnskey.algorithm,
                    "protocol": self.dnskey.protocol,
                    "flags": self.dnskey.flags,
                    "keytag": key_id(self.dnskey),
                },
            }
        )

        return json.dumps(jwk_dict)

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

        if match := re.fullmatch(
            r"K(.*\.)\+(\d{3})\+(\d{5})\.private", private_filename.name
        ):
            expected_name = _decode_name(match.group(1))
            expected_algorithm = int(match.group(2))
            expected_key_id = int(match.group(3))
        else:
            raise InvalidKeyFormat(
                f"Invalid private key filename: {private_filename.name}"
            )

        with open(private_filename, "rb") as fp:
            private_data = fp.read()

        with open(public_filename, "rb") as fp:
            public_data = fp.read()

        try:
            res = cls.from_bind_bytes(
                private_data=private_data, public_data=public_data
            )
        except (
            KeyError,
            ValueError,
            TypeError,
            SyntaxError,
            binascii.Error,
        ) as exc:
            raise InvalidKeyFormat("Failed to create key from BIND keys") from exc

        if expected_name != res.name:
            raise InvalidKeyFormat(
                f"Key name mismatch: expected {expected_name}, got {res.name}"
            )

        if expected_algorithm != res.dnskey.algorithm:
            raise InvalidKeyFormat(
                f"Algorithm mismatch: expected {expected_algorithm}, got {res.dnskey.algorithm}"
            )

        if expected_key_id != res.key_id():
            raise InvalidKeyFormat(
                f"Key ID mismatch: expected {expected_key_id}, got {res.key_id()}"
            )

        return res

    @classmethod
    def from_bind_bytes(cls, private_data: bytes, public_data: bytes) -> Self:
        """Create a key pair from BIND-style key data.

        :param private_data: The private key data.
        :type private_data: :py:class:`bytes`
        :param public_data: The public key data.
        :type public_data: :py:class:`bytes`
        :rtype: :py:class:`Key`
        """

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

        if "label" in key_dict:
            raise InvalidKeyFormat("HSM keys not supported")

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
                raise DNSException(
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

    def get_bind_private_key_filename(self) -> Path:
        """Get the filename for the BIND-style private key file.

        :rtype: Path
        """
        name = _encode_name(self.name)
        return Path(
            f"K{name}+{self.dnskey.algorithm.value:03}+{self.dnskey.key_id():05}.private"
        )

    def get_bind_public_key_filename(self) -> Path:
        """Get the filename for the BIND-style public key file.

        :rtype: Path
        """
        return self.get_bind_private_key_filename().with_suffix(".key")

    def to_bind(
        self, directory: Path | str, overwrite: bool = False, public_only: bool = False
    ) -> Path:
        """Write the key to BIND-style files and return the path to the private or public key file.

        :param directory: The path to the output directory for resulting private and public key files.
        :type directory: :py:class:`Path` or :py:class:`str`
        :param overwrite: Whether to overwrite existing key files.
        :type overwrite: bool
        :param public_only: Whether to output the public key file only.
        :type public_only: :py:class:`bool`
        :rtype: Path
        """

        if isinstance(directory, str):
            directory = Path(directory)

        if not (directory.exists() and directory.is_dir()):
            raise NotADirectoryError(f"{directory} is not a valid directory")

        public_filename = directory / self.get_bind_public_key_filename()
        private_filename = (
            directory / self.get_bind_private_key_filename()
            if not public_only
            else None
        )

        public_data = self._to_bind_public()
        private_data = self._to_bind_private() if not public_only else None

        if not overwrite:
            # Abort if the key files already exist to prevent overwriting existing keys
            if public_filename.exists():
                raise FileExistsError(
                    f"Public key file {public_filename} already exists"
                )
            if private_filename and private_filename.exists():
                raise FileExistsError(
                    f"Private key file {private_filename} already exists"
                )

        tmp_public_filename = tempfile.NamedTemporaryFile(
            dir=directory,
            prefix=f".{public_filename.name}",
            delete=False,
        ).name

        tmp_private_filename = (
            tempfile.NamedTemporaryFile(
                dir=directory,
                prefix=f".{private_filename.name}",
                delete=False,
            ).name
            if private_filename
            else None
        )

        try:

            with dns._file_util.maybe_open(
                tmp_public_filename, "wb", chmod=0o644
            ) as fp:
                fp.write(public_data)

            if tmp_private_filename is not None:
                with dns._file_util.maybe_open(
                    tmp_private_filename, "wb", chmod=0o600
                ) as fp:
                    fp.write(private_data)

            if overwrite:
                os.replace(tmp_public_filename, public_filename)
                if tmp_private_filename and private_filename:
                    os.replace(tmp_private_filename, private_filename)
            else:
                os.rename(tmp_public_filename, public_filename)
                if tmp_private_filename and private_filename:
                    os.rename(tmp_private_filename, private_filename)
        except Exception:
            # Remove any partially written key files to avoid leaving incomplete files on disk
            try:
                os.unlink(tmp_public_filename)
            except FileNotFoundError:
                pass
            if tmp_private_filename:
                os.unlink(tmp_private_filename)
            raise

        return private_filename or public_filename

    def _to_bind_public(self) -> bytes:
        """Return the public key in BIND-style format."""
        rrset = dns.rrset.from_rdata(self.name, 0, self.dnskey)
        return rrset.to_text(style=dns.rdataset.RdatasetStyle(omit_ttl=True)).encode()

    def _to_bind_private(self) -> bytes:
        """Return the private key in BIND-style format."""

        if self.private is None:
            raise InvalidKeyFormat("Private key is not set")

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
                raise DNSException(
                    f"Algorithm {self.dnskey.algorithm} not implemented when exporting private key"
                )

        return (
            b"\n".join(
                f"{key}: {value}".encode() for key, value in private_data_dict.items()
            )
            + b"\n"
        )
