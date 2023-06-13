from dns.dnssec.algbase import AlgorithmPrivateKeyBase, AlgorithmPublicKeyBase

import struct
from dataclasses import dataclass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import utils

from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


@dataclass
class PublicDSA(AlgorithmPublicKeyBase):
    public_key: dsa.DSAPublicKey
    algorithm = Algorithm.DSA
    chosen_hash = hashes.SHA1()

    def verify(self, signature: bytes, data: bytes):
        sig_r = signature[1:21]
        sig_s = signature[21:]
        sig = utils.encode_dss_signature(
            int.from_bytes(sig_r, "big"), int.from_bytes(sig_s, "big")
        )
        self.public_key.verify(sig, data, self.chosen_hash)

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 2536, section 2."""
        pn = self.public_key.public_numbers()
        dsa_t = (self.public_key.key_size // 8 - 64) // 8
        if dsa_t > 8:
            raise ValueError("unsupported DSA key size")
        octets = 64 + dsa_t * 8
        res = struct.pack("!B", dsa_t)
        res += pn.parameter_numbers.q.to_bytes(20, "big")
        res += pn.parameter_numbers.p.to_bytes(octets, "big")
        res += pn.parameter_numbers.g.to_bytes(octets, "big")
        res += pn.y.to_bytes(octets, "big")
        return res

    @classmethod
    def from_dnskey(cls, key: DNSKEY):
        keyptr = key.key
        (t,) = struct.unpack("!B", keyptr[0:1])
        keyptr = keyptr[1:]
        octets = 64 + t * 8
        dsa_q = keyptr[0:20]
        keyptr = keyptr[20:]
        dsa_p = keyptr[0:octets]
        keyptr = keyptr[octets:]
        dsa_g = keyptr[0:octets]
        keyptr = keyptr[octets:]
        dsa_y = keyptr[0:octets]
        return cls(
            public_key=dsa.DSAPublicNumbers(  # type: ignore
                int.from_bytes(dsa_y, "big"),
                dsa.DSAParameterNumbers(
                    int.from_bytes(dsa_p, "big"),
                    int.from_bytes(dsa_q, "big"),
                    int.from_bytes(dsa_g, "big"),
                ),
            ).public_key(default_backend()),
            algorithm=cls.algorithm,
        )


@dataclass
class PrivateDSA(AlgorithmPrivateKeyBase):
    private_key: dsa.DSAPrivateKey
    public_cls = PublicDSA

    def sign(self, data: bytes, verify: bool = False) -> bytes:
        public_dsa_key = self.private_key.public_key()
        if public_dsa_key.key_size > 1024:
            raise ValueError("DSA key size overflow")
        der_signature = self.private_key.sign(data, self.public_cls.chosen_hash)
        if verify:
            public_dsa_key.verify(der_signature, data, self.public_cls.chosen_hash)
        dsa_r, dsa_s = utils.decode_dss_signature(der_signature)
        dsa_t = (public_dsa_key.key_size // 8 - 64) // 8
        octets = 20
        return (
            struct.pack("!B", dsa_t)
            + int.to_bytes(dsa_r, length=octets, byteorder="big")
            + int.to_bytes(dsa_s, length=octets, byteorder="big")
        )

    def public_key(self) -> "PublicDSA":
        return self.public_cls(
            public_key=self.private_key.public_key(),
            algorithm=self.public_cls.algorithm,
        )

    @classmethod
    def generate(cls, key_size: int):
        return cls(
            private_key=dsa.generate_private_key(key_size=key_size),
            public_cls=cls.public_cls,
        )


@dataclass
class PublicDSANSEC3SHA1(PublicDSA):
    algorithm = Algorithm.DSANSEC3SHA1


@dataclass
class PrivateDSANSEC3SHA1(PrivateDSA):
    public_cls = PublicDSANSEC3SHA1
