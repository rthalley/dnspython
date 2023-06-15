from dataclasses import dataclass

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from dns.dnssecalgs.base import AlgorithmPrivateKeyBase, AlgorithmPublicKeyBase
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY


@dataclass
class PublicECDSA(AlgorithmPublicKeyBase):
    key: ec.EllipticCurvePublicKey
    chosen_hash = None
    curve = None
    octets = None
    key_cls = ec.EllipticCurvePublicKey

    def verify(self, signature: bytes, data: bytes):
        sig_r = signature[0 : self.octets]
        sig_s = signature[self.octets :]
        sig = utils.encode_dss_signature(
            int.from_bytes(sig_r, "big"), int.from_bytes(sig_s, "big")
        )
        self.key.verify(sig, data, ec.ECDSA(self.chosen_hash))

    def encode_key_bytes(self) -> bytes:
        """Encode a public key per RFC 6605, section 4."""
        pn = self.key.public_numbers()
        return pn.x.to_bytes(self.octets, "big") + pn.y.to_bytes(self.octets, "big")

    @classmethod
    def from_dnskey(cls, key: DNSKEY):
        ecdsa_x = key.key[0 : cls.octets]
        ecdsa_y = key.key[cls.octets : cls.octets * 2]
        return cls(
            key=ec.EllipticCurvePublicNumbers(
                curve=cls.curve,
                x=int.from_bytes(ecdsa_x, "big"),
                y=int.from_bytes(ecdsa_y, "big"),
            ).public_key(default_backend()),
            algorithm=cls.algorithm,
        )


@dataclass
class PrivateECDSA(AlgorithmPrivateKeyBase):
    key: ec.EllipticCurvePrivateKey
    public_cls = None
    key_cls = ec.EllipticCurvePrivateKey

    def sign(self, data: bytes, verify: bool = False) -> bytes:
        """Sign using a private key per RFC 6605, section 4."""
        der_signature = self.key.sign(
            data, ec.ECDSA(self.public_cls.chosen_hash)
        )
        if verify:
            self.key.public_key().verify(
                der_signature, data, ec.ECDSA(self.public_cls.chosen_hash)
            )
        dsa_r, dsa_s = utils.decode_dss_signature(der_signature)
        return int.to_bytes(
            dsa_r, length=self.public_cls.octets, byteorder="big"
        ) + int.to_bytes(dsa_s, length=self.public_cls.octets, byteorder="big")

    def public_key(self) -> "PublicECDSA":
        return self.public_cls(
            key=self.key.public_key(),
            algorithm=self.public_cls.algorithm,
        )

    @classmethod
    def generate(cls):
        return cls(
            key=ec.generate_private_key(
                curve=cls.public_cls.curve, backend=default_backend()
            ),
            public_cls=cls.public_cls,
        )


@dataclass
class PublicECDSAP256SHA256(PublicECDSA):
    algorithm = Algorithm.ECDSAP256SHA256
    chosen_hash = hashes.SHA256()
    curve = ec.SECP256R1()
    octets = 32


@dataclass
class PrivateECDSAP256SHA256(PrivateECDSA):
    public_cls = PublicECDSAP256SHA256


@dataclass
class PublicECDSAP384SHA384(PublicECDSA):
    algorithm = Algorithm.ECDSAP384SHA384
    chosen_hash = hashes.SHA384()
    curve = ec.SECP384R1()
    octets = 48


@dataclass
class PrivateECDSAP384SHA384(PrivateECDSA):
    public_cls = PublicECDSAP384SHA384
