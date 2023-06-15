import math
import struct
from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from dns.dnssecalgs.base import AlgorithmPrivateKeyBase, AlgorithmPublicKeyBase
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


@dataclass
class PublicRSA(AlgorithmPublicKeyBase):
    public_key: rsa.RSAPublicKey
    algorithm = None
    chosen_hash = None
    key_cls = rsa.RSAPublicKey

    def verify(self, signature: bytes, data: bytes):
        self.public_key.verify(signature, data, padding.PKCS1v15(), self.chosen_hash)

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 3110, section 2."""
        pn = self.public_key.public_numbers()
        _exp_len = math.ceil(int.bit_length(pn.e) / 8)
        exp = int.to_bytes(pn.e, length=_exp_len, byteorder="big")
        if _exp_len > 255:
            exp_header = b"\0" + struct.pack("!H", _exp_len)
        else:
            exp_header = struct.pack("!B", _exp_len)
        if pn.n.bit_length() < 512 or pn.n.bit_length() > 4096:
            raise ValueError("unsupported RSA key length")
        return exp_header + exp + pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")

    @classmethod
    def from_dnskey(cls, key: DNSKEY):
        keyptr = key.key
        (bytes_,) = struct.unpack("!B", keyptr[0:1])
        keyptr = keyptr[1:]
        if bytes_ == 0:
            (bytes_,) = struct.unpack("!H", keyptr[0:2])
            keyptr = keyptr[2:]
        rsa_e = keyptr[0:bytes_]
        rsa_n = keyptr[bytes_:]
        return cls(
            public_key=rsa.RSAPublicNumbers(
                int.from_bytes(rsa_e, "big"), int.from_bytes(rsa_n, "big")
            ).public_key(default_backend()),
            algorithm=cls.algorithm,
        )


@dataclass
class PrivateRSA(AlgorithmPrivateKeyBase):
    private_key: rsa.RSAPrivateKey
    default_public_exponent = 65537
    key_cls = rsa.RSAPrivateKey

    def sign(self, data: bytes, verify: bool = False) -> bytes:
        """Sign using a private key per RFC 3110, section 3."""
        signature = self.private_key.sign(
            data, padding.PKCS1v15(), self.public_cls.chosen_hash
        )
        if verify:
            self.private_key.public_key().verify(
                signature, data, padding.PKCS1v15(), self.public_cls.chosen_hash
            )
        return signature

    def public_key(self) -> "PublicRSA":
        return self.public_cls(
            public_key=self.private_key.public_key(),
            algorithm=self.public_cls.algorithm,
        )

    @classmethod
    def generate(cls, key_size: int):
        return cls(
            private_key=rsa.generate_private_key(
                public_exponent=cls.default_public_exponent,
                key_size=key_size,
                backend=default_backend(),
            ),
            public_cls=cls.public_cls,
        )


@dataclass
class PublicRSAMD5(PublicRSA):
    algorithm = Algorithm.RSAMD5
    chosen_hash = hashes.MD5()


@dataclass
class PrivateRSAMD5(PrivateRSA):
    algorithm = Algorithm.RSAMD5
    chosen_hash = hashes.MD5()
    public_cls = PublicRSAMD5


@dataclass
class PublicRSASHA1(PublicRSA):
    algorithm = Algorithm.RSASHA1
    chosen_hash = hashes.SHA1()


@dataclass
class PrivateRSASHA1(PrivateRSA):
    public_cls = PublicRSASHA1


@dataclass
class PublicRSASHA1NSEC3SHA1(PublicRSA):
    algorithm = Algorithm.RSASHA1NSEC3SHA1
    chosen_hash = hashes.SHA1()


@dataclass
class PrivateRSASHA1NSEC3SHA1(PrivateRSA):
    public_cls = PublicRSASHA1NSEC3SHA1


@dataclass
class PublicRSASHA256(PublicRSA):
    algorithm = Algorithm.RSASHA256
    chosen_hash = hashes.SHA256()


@dataclass
class PrivateRSASHA256(PrivateRSA):
    public_cls = PublicRSASHA256


@dataclass
class PublicRSASHA512(PublicRSA):
    algorithm = Algorithm.RSASHA512
    chosen_hash = hashes.SHA512()


@dataclass
class PrivateRSASHA512(PrivateRSA):
    public_cls = PublicRSASHA512
