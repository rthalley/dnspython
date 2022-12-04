# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Common DNSSEC-related functions and constants."""

from typing import Any, cast, Dict, List, Optional, Tuple, Union

import hashlib
import math
import struct
import time
import base64

from dns.dnssectypes import Algorithm, DSDigest, NSEC3Hash

import dns.exception
import dns.name
import dns.node
import dns.rdataset
import dns.rdata
import dns.rdatatype
import dns.rdataclass
import dns.rrset
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.RRSIG import RRSIG
from dns.rdtypes.dnskeybase import Flag


class UnsupportedAlgorithm(dns.exception.DNSException):
    """The DNSSEC algorithm is not supported."""


class ValidationFailure(dns.exception.DNSException):
    """The DNSSEC signature is invalid."""


def algorithm_from_text(text: str) -> Algorithm:
    """Convert text into a DNSSEC algorithm value.

    *text*, a ``str``, the text to convert to into an algorithm value.

    Returns an ``int``.
    """

    return Algorithm.from_text(text)


def algorithm_to_text(value: Union[Algorithm, int]) -> str:
    """Convert a DNSSEC algorithm value to text

    *value*, a ``dns.dnssec.Algorithm``.

    Returns a ``str``, the name of a DNSSEC algorithm.
    """

    return Algorithm.to_text(value)


def key_id(key: DNSKEY) -> int:
    """Return the key id (a 16-bit number) for the specified key.

    *key*, a ``dns.rdtypes.ANY.DNSKEY.DNSKEY``

    Returns an ``int`` between 0 and 65535
    """

    rdata = key.to_wire()
    if key.algorithm == Algorithm.RSAMD5:
        return (rdata[-3] << 8) + rdata[-2]
    else:
        total = 0
        for i in range(len(rdata) // 2):
            total += (rdata[2 * i] << 8) + rdata[2 * i + 1]
        if len(rdata) % 2 != 0:
            total += rdata[len(rdata) - 1] << 8
        total += (total >> 16) & 0xFFFF
        return total & 0xFFFF


def make_ds(
    name: Union[dns.name.Name, str],
    key: dns.rdata.Rdata,
    algorithm: Union[DSDigest, str],
    origin: Optional[dns.name.Name] = None,
) -> DS:
    """Create a DS record for a DNSSEC key.

    *name*, a ``dns.name.Name`` or ``str``, the owner name of the DS record.

    *key*, a ``dns.rdtypes.ANY.DNSKEY.DNSKEY``, the key the DS is about.

    *algorithm*, a ``str`` or ``int`` specifying the hash algorithm.
    The currently supported hashes are "SHA1", "SHA256", and "SHA384". Case
    does not matter for these strings.

    *origin*, a ``dns.name.Name`` or ``None``.  If `key` is a relative name,
    then it will be made absolute using the specified origin.

    Raises ``UnsupportedAlgorithm`` if the algorithm is unknown.

    Returns a ``dns.rdtypes.ANY.DS.DS``
    """

    try:
        if isinstance(algorithm, str):
            algorithm = DSDigest[algorithm.upper()]
    except Exception:
        raise UnsupportedAlgorithm('unsupported algorithm "%s"' % algorithm)
    if not isinstance(key, DNSKEY):
        raise ValueError("key is not a DNSKEY")
    if algorithm == DSDigest.SHA1:
        dshash = hashlib.sha1()
    elif algorithm == DSDigest.SHA256:
        dshash = hashlib.sha256()
    elif algorithm == DSDigest.SHA384:
        dshash = hashlib.sha384()
    else:
        raise UnsupportedAlgorithm('unsupported algorithm "%s"' % algorithm)

    if isinstance(name, str):
        name = dns.name.from_text(name, origin)
    wire = name.canonicalize().to_wire()
    assert wire is not None
    dshash.update(wire)
    dshash.update(key.to_wire(origin=origin))
    digest = dshash.digest()

    dsrdata = struct.pack("!HBB", key_id(key), key.algorithm, algorithm) + digest
    ds = dns.rdata.from_wire(
        dns.rdataclass.IN, dns.rdatatype.DS, dsrdata, 0, len(dsrdata)
    )
    return cast(DS, ds)


def _find_candidate_keys(
    keys: Dict[dns.name.Name, Union[dns.rdataset.Rdataset, dns.node.Node]], rrsig: RRSIG
) -> Optional[List[DNSKEY]]:
    value = keys.get(rrsig.signer)
    if isinstance(value, dns.node.Node):
        rdataset = value.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    else:
        rdataset = value
    if rdataset is None:
        return None
    return [
        cast(DNSKEY, rd)
        for rd in rdataset
        if rd.algorithm == rrsig.algorithm and key_id(rd) == rrsig.key_tag
    ]


def _is_rsa(algorithm: int) -> bool:
    return algorithm in (
        Algorithm.RSAMD5,
        Algorithm.RSASHA1,
        Algorithm.RSASHA1NSEC3SHA1,
        Algorithm.RSASHA256,
        Algorithm.RSASHA512,
    )


def _is_dsa(algorithm: int) -> bool:
    return algorithm in (Algorithm.DSA, Algorithm.DSANSEC3SHA1)


def _is_ecdsa(algorithm: int) -> bool:
    return algorithm in (Algorithm.ECDSAP256SHA256, Algorithm.ECDSAP384SHA384)


def _is_eddsa(algorithm: int) -> bool:
    return algorithm in (Algorithm.ED25519, Algorithm.ED448)


def _is_gost(algorithm: int) -> bool:
    return algorithm == Algorithm.ECCGOST


def _is_md5(algorithm: int) -> bool:
    return algorithm == Algorithm.RSAMD5


def _is_sha1(algorithm: int) -> bool:
    return algorithm in (
        Algorithm.DSA,
        Algorithm.RSASHA1,
        Algorithm.DSANSEC3SHA1,
        Algorithm.RSASHA1NSEC3SHA1,
    )


def _is_sha256(algorithm: int) -> bool:
    return algorithm in (Algorithm.RSASHA256, Algorithm.ECDSAP256SHA256)


def _is_sha384(algorithm: int) -> bool:
    return algorithm == Algorithm.ECDSAP384SHA384


def _is_sha512(algorithm: int) -> bool:
    return algorithm == Algorithm.RSASHA512


def _make_hash(algorithm: int) -> Any:
    if _is_md5(algorithm):
        return hashes.MD5()
    if _is_sha1(algorithm):
        return hashes.SHA1()
    if _is_sha256(algorithm):
        return hashes.SHA256()
    if _is_sha384(algorithm):
        return hashes.SHA384()
    if _is_sha512(algorithm):
        return hashes.SHA512()
    if algorithm == Algorithm.ED25519:
        return hashes.SHA512()
    if algorithm == Algorithm.ED448:
        return hashes.SHAKE256(114)

    raise ValidationFailure("unknown hash for algorithm %u" % algorithm)


def _bytes_to_long(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _validate_signature(sig: bytes, data: bytes, key: DNSKEY, chosen_hash: Any) -> None:
    keyptr: bytes
    if _is_rsa(key.algorithm):
        # we ignore because mypy is confused and thinks key.key is a str for unknown
        # reasons.
        keyptr = key.key
        (bytes_,) = struct.unpack("!B", keyptr[0:1])
        keyptr = keyptr[1:]
        if bytes_ == 0:
            (bytes_,) = struct.unpack("!H", keyptr[0:2])
            keyptr = keyptr[2:]
        rsa_e = keyptr[0:bytes_]
        rsa_n = keyptr[bytes_:]
        try:
            rsa_public_key = rsa.RSAPublicNumbers(
                _bytes_to_long(rsa_e), _bytes_to_long(rsa_n)
            ).public_key(default_backend())
        except ValueError:
            raise ValidationFailure("invalid public key")
        rsa_public_key.verify(sig, data, padding.PKCS1v15(), chosen_hash)
    elif _is_dsa(key.algorithm):
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
        try:
            dsa_public_key = dsa.DSAPublicNumbers(  # type: ignore
                _bytes_to_long(dsa_y),
                dsa.DSAParameterNumbers(
                    _bytes_to_long(dsa_p), _bytes_to_long(dsa_q), _bytes_to_long(dsa_g)
                ),
            ).public_key(default_backend())
        except ValueError:
            raise ValidationFailure("invalid public key")
        dsa_public_key.verify(sig, data, chosen_hash)
    elif _is_ecdsa(key.algorithm):
        keyptr = key.key
        curve: Any
        if key.algorithm == Algorithm.ECDSAP256SHA256:
            curve = ec.SECP256R1()
            octets = 32
        else:
            curve = ec.SECP384R1()
            octets = 48
        ecdsa_x = keyptr[0:octets]
        ecdsa_y = keyptr[octets : octets * 2]
        try:
            ecdsa_public_key = ec.EllipticCurvePublicNumbers(
                curve=curve, x=_bytes_to_long(ecdsa_x), y=_bytes_to_long(ecdsa_y)
            ).public_key(default_backend())
        except ValueError:
            raise ValidationFailure("invalid public key")
        ecdsa_public_key.verify(sig, data, ec.ECDSA(chosen_hash))
    elif _is_eddsa(key.algorithm):
        keyptr = key.key
        loader: Any
        if key.algorithm == Algorithm.ED25519:
            loader = ed25519.Ed25519PublicKey
        else:
            loader = ed448.Ed448PublicKey
        try:
            eddsa_public_key = loader.from_public_bytes(keyptr)
        except ValueError:
            raise ValidationFailure("invalid public key")
        eddsa_public_key.verify(sig, data)
    elif _is_gost(key.algorithm):
        raise UnsupportedAlgorithm(
            'algorithm "%s" not supported by dnspython'
            % algorithm_to_text(key.algorithm)
        )
    else:
        raise ValidationFailure("unknown algorithm %u" % key.algorithm)


def _validate_rrsig(
    rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]],
    rrsig: RRSIG,
    keys: Dict[dns.name.Name, Union[dns.node.Node, dns.rdataset.Rdataset]],
    origin: Optional[dns.name.Name] = None,
    now: Optional[float] = None,
) -> None:
    """Validate an RRset against a single signature rdata, throwing an
    exception if validation is not successful.

    *rrset*, the RRset to validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *rrsig*, a ``dns.rdata.Rdata``, the signature to validate.

    *keys*, the key dictionary, used to find the DNSKEY associated
    with a given name.  The dictionary is keyed by a
    ``dns.name.Name``, and has ``dns.node.Node`` or
    ``dns.rdataset.Rdataset`` values.

    *origin*, a ``dns.name.Name`` or ``None``, the origin to use for relative
    names.

    *now*, a ``float`` or ``None``, the time, in seconds since the epoch, to
    use as the current time when validating.  If ``None``, the actual current
    time is used.

    Raises ``ValidationFailure`` if the signature is expired, not yet valid,
    the public key is invalid, the algorithm is unknown, the verification
    fails, etc.

    Raises ``UnsupportedAlgorithm`` if the algorithm is recognized by
    dnspython but not implemented.
    """

    candidate_keys = _find_candidate_keys(keys, rrsig)
    if candidate_keys is None:
        raise ValidationFailure("unknown key")

    if now is None:
        now = time.time()
    if rrsig.expiration < now:
        raise ValidationFailure("expired")
    if rrsig.inception > now:
        raise ValidationFailure("not yet valid")

    if _is_dsa(rrsig.algorithm):
        sig_r = rrsig.signature[1:21]
        sig_s = rrsig.signature[21:]
        sig = utils.encode_dss_signature(_bytes_to_long(sig_r), _bytes_to_long(sig_s))
    elif _is_ecdsa(rrsig.algorithm):
        if rrsig.algorithm == Algorithm.ECDSAP256SHA256:
            octets = 32
        else:
            octets = 48
        sig_r = rrsig.signature[0:octets]
        sig_s = rrsig.signature[octets:]
        sig = utils.encode_dss_signature(_bytes_to_long(sig_r), _bytes_to_long(sig_s))
    else:
        sig = rrsig.signature

    data = _make_rrsig_signature_data(rrset, rrsig, origin)
    chosen_hash = _make_hash(rrsig.algorithm)

    for candidate_key in candidate_keys:
        try:
            _validate_signature(sig, data, candidate_key, chosen_hash)
            return
        except (InvalidSignature, ValidationFailure):
            # this happens on an individual validation failure
            continue
    # nothing verified -- raise failure:
    raise ValidationFailure("verify failure")


def _validate(
    rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]],
    rrsigset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]],
    keys: Dict[dns.name.Name, Union[dns.node.Node, dns.rdataset.Rdataset]],
    origin: Optional[dns.name.Name] = None,
    now: Optional[float] = None,
) -> None:
    """Validate an RRset against a signature RRset, throwing an exception
    if none of the signatures validate.

    *rrset*, the RRset to validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *rrsigset*, the signature RRset.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *keys*, the key dictionary, used to find the DNSKEY associated
    with a given name.  The dictionary is keyed by a
    ``dns.name.Name``, and has ``dns.node.Node`` or
    ``dns.rdataset.Rdataset`` values.

    *origin*, a ``dns.name.Name``, the origin to use for relative names;
    defaults to None.

    *now*, an ``int`` or ``None``, the time, in seconds since the epoch, to
    use as the current time when validating.  If ``None``, the actual current
    time is used.

    Raises ``ValidationFailure`` if the signature is expired, not yet valid,
    the public key is invalid, the algorithm is unknown, the verification
    fails, etc.
    """

    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)

    if isinstance(rrset, tuple):
        rrname = rrset[0]
    else:
        rrname = rrset.name

    if isinstance(rrsigset, tuple):
        rrsigname = rrsigset[0]
        rrsigrdataset = rrsigset[1]
    else:
        rrsigname = rrsigset.name
        rrsigrdataset = rrsigset

    rrname = rrname.choose_relativity(origin)
    rrsigname = rrsigname.choose_relativity(origin)
    if rrname != rrsigname:
        raise ValidationFailure("owner names do not match")

    for rrsig in rrsigrdataset:
        if not isinstance(rrsig, RRSIG):
            raise ValidationFailure("expected an RRSIG")
        try:
            _validate_rrsig(rrset, rrsig, keys, origin, now)
            return
        except (ValidationFailure, UnsupportedAlgorithm):
            pass
    raise ValidationFailure("no RRSIGs validated")


def _make_rrsig_signature_data(
    rrset: Union[dns.rrset.RRset, Tuple[dns.name.Name, dns.rdataset.Rdataset]],
    rrsig: RRSIG,
    origin: Optional[dns.name.Name] = None
) -> bytes:
    """Create signature rdata.

    *rrset*, the RRset to sign/validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    *rrsig*, a ``dns.rdata.Rdata``, the signature to validate, or the
    signature template when signing

    *origin*, a ``dns.name.Name`` or ``None``, the origin to use for relative
    names.

    Raises ``UnsupportedAlgorithm`` if the algorithm is recognized by
    dnspython but not implemented.
    """

    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)
    
    signer = rrsig.signer
    if not signer.is_absolute():
        if origin is None:
            raise ValidationFailure("relative RR name without an origin specified")
        signer = signer.derelativize(origin)

    # For convenience, allow the rrset to be specified as a (name,
    # rdataset) tuple as well as a proper rrset
    if isinstance(rrset, tuple):
        rrname = rrset[0]
        rdataset = rrset[1]
    else:
        rrname = rrset.name
        rdataset = rrset

    data = b""
    data += rrsig.to_wire(origin=signer)[:18]
    data += rrsig.signer.to_digestable(signer)

    # Derelativize the name before considering labels.
    if not rrname.is_absolute():
        if origin is None:
            raise ValidationFailure("relative RR name without an origin specified")
        rrname = rrname.derelativize(origin)

    if len(rrname) - 1 < rrsig.labels:
        raise ValidationFailure("owner name longer than RRSIG labels")
    elif rrsig.labels < len(rrname) - 1:
        suffix = rrname.split(rrsig.labels + 1)[1]
        rrname = dns.name.from_text("*", suffix)
    rrnamebuf = rrname.to_digestable()
    rrfixed = struct.pack("!HHI", rdataset.rdtype, rdataset.rdclass, rrsig.original_ttl)
    rdatas = [rdata.to_digestable(origin) for rdata in rdataset]
    for rdata in sorted(rdatas):
        data += rrnamebuf
        data += rrfixed
        rrlen = struct.pack("!H", len(rdata))
        data += rrlen
        data += rdata

    return data


def _make_dnskey(
    public_key,
    algorithm: Union[int, str],
    flags: int = Flag.ZONE,
    protocol: int = 3,
) -> DNSKEY:
    """Convert a public key to DNSKEY Rdata

    *public_key*, the public key to convert, a
    ``cryptography.hazmat.primitives.asymmetric`` public key class applicable
    for DNSSEC.

    *algorithm*, a ``str`` or ``int`` specifying the DNSKEY algorithm.

    *flags: DNSKEY flags field as an integer.

    *protocol*: DNSKEY protocol field as an integer.

    Raises ``ValueError`` if the specified algorithm is unsupported or
    ``TypeError`` if the key algorithm is unsupported.

    Return DNSKEY ``Rdata``.
    """

    def encode_rsa_public_key(public_key) -> bytes:
        """Encode a public key as RFC 3110, section 2."""
        pn = public_key.public_numbers()
        _exp_len = math.ceil(int.bit_length(pn.e) / 8)
        exp = int.to_bytes(pn.e, length=_exp_len, byteorder="big")
        if _exp_len > 255:
            exp_header = b"\0" + struct.pack("!H", _exp_len)
        else:
            exp_header = struct.pack("!B", _exp_len)
        if pn.n.bit_length() < 512 or pn.n.bit_length() > 4096:
            raise ValueError("Unsupported RSA key length")
        return exp_header + exp + pn.n.to_bytes((pn.n.bit_length() + 7) // 8, "big")

    def encode_ecdsa_public_key(public_key) -> bytes:
        pn = public_key.public_numbers()
        if isinstance(public_key.curve, ec.SECP256R1):
            return pn.x.to_bytes(32, "big") + pn.y.to_bytes(32, "big")
        elif isinstance(public_key.curve, ec.SECP384R1):
            return pn.x.to_bytes(48, "big") + pn.y.to_bytes(48, "big")
        else:
            raise ValueError("Unsupported ECDSA curve")

    try:
        if isinstance(algorithm, str):
            algorithm = Algorithm[algorithm.upper()]
    except Exception:
        raise UnsupportedAlgorithm('unsupported algorithm "%s"' % algorithm)

    if isinstance(public_key, rsa.RSAPublicKey):
        if not _is_rsa(algorithm):
            raise ValueError("Invalid DNSKEY algorithm for RSA key")
        key_bytes = encode_rsa_public_key(public_key)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if not _is_ecdsa(algorithm):
            raise ValueError("Invalid DNSKEY algorithm for EC key")
        key_bytes = encode_ecdsa_public_key(public_key)
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        if algorithm != Algorithm.ED25519:
            raise ValueError("Invalid DNSKEY algorithm for ED25519 key")
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    elif isinstance(public_key, ed448.Ed448PublicKey):
        if algorithm != Algorithm.ED448:
            raise ValueError("Invalid DNSKEY algorithm for ED448 key")
        key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    else:
        raise TypeError("Unsupported key algorithm")

    return DNSKEY(
        rdclass=dns.rdataclass.IN,
        rdtype=dns.rdatatype.DNSKEY,
        flags=flags,
        protocol=protocol,
        algorithm=algorithm,
        key=key_bytes,
    )


def nsec3_hash(
    domain: Union[dns.name.Name, str],
    salt: Optional[Union[str, bytes]],
    iterations: int,
    algorithm: Union[int, str],
) -> str:
    """
    Calculate the NSEC3 hash, according to
    https://tools.ietf.org/html/rfc5155#section-5

    *domain*, a ``dns.name.Name`` or ``str``, the name to hash.

    *salt*, a ``str``, ``bytes``, or ``None``, the hash salt.  If a
    string, it is decoded as a hex string.

    *iterations*, an ``int``, the number of iterations.

    *algorithm*, a ``str`` or ``int``, the hash algorithm.
    The only defined algorithm is SHA1.

    Returns a ``str``, the encoded NSEC3 hash.
    """

    b32_conversion = str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV"
    )

    try:
        if isinstance(algorithm, str):
            algorithm = NSEC3Hash[algorithm.upper()]
    except Exception:
        raise ValueError("Wrong hash algorithm (only SHA1 is supported)")

    if algorithm != NSEC3Hash.SHA1:
        raise ValueError("Wrong hash algorithm (only SHA1 is supported)")

    if salt is None:
        salt_encoded = b""
    elif isinstance(salt, str):
        if len(salt) % 2 == 0:
            salt_encoded = bytes.fromhex(salt)
        else:
            raise ValueError("Invalid salt length")
    else:
        salt_encoded = salt

    if not isinstance(domain, dns.name.Name):
        domain = dns.name.from_text(domain)
    domain_encoded = domain.canonicalize().to_wire()
    assert domain_encoded is not None

    digest = hashlib.sha1(domain_encoded + salt_encoded).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt_encoded).digest()

    output = base64.b32encode(digest).decode("utf-8")
    output = output.translate(b32_conversion)

    return output


def _need_pyca(*args, **kwargs):
    raise ImportError(
        "DNSSEC validation requires " + "python cryptography"
    )  # pragma: no cover


try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.asymmetric import utils
    from cryptography.hazmat.primitives.asymmetric import dsa
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.asymmetric import ed448
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:  # pragma: no cover
    validate = _need_pyca
    validate_rrsig = _need_pyca
    make_dnskey = _need_pyca
    _have_pyca = False
else:
    validate = _validate  # type: ignore
    validate_rrsig = _validate_rrsig  # type: ignore
    make_dnskey = _make_dnskey
    _have_pyca = True

### BEGIN generated Algorithm constants

RSAMD5 = Algorithm.RSAMD5
DH = Algorithm.DH
DSA = Algorithm.DSA
ECC = Algorithm.ECC
RSASHA1 = Algorithm.RSASHA1
DSANSEC3SHA1 = Algorithm.DSANSEC3SHA1
RSASHA1NSEC3SHA1 = Algorithm.RSASHA1NSEC3SHA1
RSASHA256 = Algorithm.RSASHA256
RSASHA512 = Algorithm.RSASHA512
ECCGOST = Algorithm.ECCGOST
ECDSAP256SHA256 = Algorithm.ECDSAP256SHA256
ECDSAP384SHA384 = Algorithm.ECDSAP384SHA384
ED25519 = Algorithm.ED25519
ED448 = Algorithm.ED448
INDIRECT = Algorithm.INDIRECT
PRIVATEDNS = Algorithm.PRIVATEDNS
PRIVATEOID = Algorithm.PRIVATEOID

### END generated Algorithm constants
