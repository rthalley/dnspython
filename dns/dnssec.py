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

import hashlib  # used in make_ds() to avoid pycrypto dependency
from io import BytesIO
import struct
import sys
import time

import dns.exception
import dns.name
import dns.node
import dns.rdataset
import dns.rdata
import dns.rdatatype
import dns.rdataclass


class UnsupportedAlgorithm(dns.exception.DNSException):
    """The DNSSEC algorithm is not supported."""


class ValidationFailure(dns.exception.DNSException):
    """The DNSSEC signature is invalid."""


#: RSAMD5
RSAMD5 = 1
#: DH
DH = 2
#: DSA
DSA = 3
#: ECC
ECC = 4
#: RSASHA1
RSASHA1 = 5
#: DSANSEC3SHA1
DSANSEC3SHA1 = 6
#: RSASHA1NSEC3SHA1
RSASHA1NSEC3SHA1 = 7
#: RSASHA256
RSASHA256 = 8
#: RSASHA512
RSASHA512 = 10
#: ECC-GOST
ECCGOST = 12
#: ECDSAP256SHA256
ECDSAP256SHA256 = 13
#: ECDSAP384SHA384
ECDSAP384SHA384 = 14
#: ED25519
ED25519 = 15
#: ED448
ED448 = 16
#: INDIRECT
INDIRECT = 252
#: PRIVATEDNS
PRIVATEDNS = 253
#: PRIVATEOID
PRIVATEOID = 254

_algorithm_by_text = {
    'RSAMD5': RSAMD5,
    'DH': DH,
    'DSA': DSA,
    'ECC': ECC,
    'RSASHA1': RSASHA1,
    'DSANSEC3SHA1': DSANSEC3SHA1,
    'RSASHA1NSEC3SHA1': RSASHA1NSEC3SHA1,
    'RSASHA256': RSASHA256,
    'RSASHA512': RSASHA512,
    'ECCGOST': ECCGOST,
    'ECDSAP256SHA256': ECDSAP256SHA256,
    'ECDSAP384SHA384': ECDSAP384SHA384,
    'ED25519': ED25519,
    'ED448': ED448,
    'INDIRECT': INDIRECT,
    'PRIVATEDNS': PRIVATEDNS,
    'PRIVATEOID': PRIVATEOID,
}

# We construct the inverse mapping programmatically to ensure that we
# cannot make any mistakes (e.g. omissions, cut-and-paste errors) that
# would cause the mapping not to be true inverse.

_algorithm_by_value = {y: x for x, y in _algorithm_by_text.items()}


def algorithm_from_text(text):
    """Convert text into a DNSSEC algorithm value.

    :param text: text to convert to value
    :type text: string
    :return: a DNSSEC algorithm value
    :rtype: integer
    """

    value = _algorithm_by_text.get(text.upper())
    if value is None:
        value = int(text)
    return value


def algorithm_to_text(value):
    """Convert a DNSSEC algorithm value to text

    :param value: Value of a DNSSEC algorithm
    :type value: integer
    :return: the name of a DNSSEC algorithm
    :rtype: string
    """

    text = _algorithm_by_value.get(value)
    if text is None:
        text = str(value)
    return text


def _to_rdata(record, origin):
    s = BytesIO()
    record.to_wire(s, origin=origin)
    return s.getvalue()


def key_id(key, origin=None):
    """Return the key id (a 16-bit number) for the specified key.

    :param key: a DNSKEY
    :type key: :py:data:`dns.rdtypes.ANY.DNSKEY`
    :param origin: Parameter is historical and **NOT** needed, defaults to None
    :type origin: [type], optional
    :return: an integer between 0 and 65535
    :rtype: integer

    """

    rdata = _to_rdata(key, origin)
    if key.algorithm == RSAMD5:
        return (rdata[-3] << 8) + rdata[-2]
    else:
        total = 0
        for i in range(len(rdata) // 2):
            total += (rdata[2 * i] << 8) + \
                rdata[2 * i + 1]
        if len(rdata) % 2 != 0:
            total += rdata[len(rdata) - 1] << 8
        total += ((total >> 16) & 0xffff)
        return total & 0xffff


def make_ds(name, key, algorithm, origin=None):
    """Create a DS record for a DNSSEC key.

    :param name: Owner name of the DS record
    :type name: string
    :param key: a DNSKEY
    :type key: :py:data:`dns.rdtypes.ANY.DNSKEY`
    :param algorithm: a string describing which hash algorithm to
    use.  The currently supported hashes are "SHA1" and "SHA256". Case
    does not matter for these strings.
    :type algorithm: string
    :param origin: Will be used as origin if `key` is a relative name,
    defaults to None
    :type origin: :py:data:`dns.name.Name`, optional
    :raises UnsupportedAlgorithm: If the algorithm is not either
    "SHA1" or "SHA256" exception will be thrown
    :return: a DS record
    :rtype: :py:data:`dns.rdtypes.ANY.DS`

    """

    if algorithm.upper() == 'SHA1':
        dsalg = 1
        dshash = hashlib.sha1()
    elif algorithm.upper() == 'SHA256':
        dsalg = 2
        dshash = hashlib.sha256()
    else:
        raise UnsupportedAlgorithm('unsupported algorithm "%s"' % algorithm)

    if isinstance(name, str):
        name = dns.name.from_text(name, origin)
    dshash.update(name.canonicalize().to_wire())
    dshash.update(_to_rdata(key, origin))
    digest = dshash.digest()

    dsrdata = struct.pack("!HBB", key_id(key), key.algorithm, dsalg) + digest
    return dns.rdata.from_wire(dns.rdataclass.IN, dns.rdatatype.DS, dsrdata, 0,
                               len(dsrdata))


def _find_candidate_keys(keys, rrsig):
    candidate_keys = []
    value = keys.get(rrsig.signer)
    if value is None:
        return None
    if isinstance(value, dns.node.Node):
        try:
            rdataset = value.find_rdataset(dns.rdataclass.IN,
                                           dns.rdatatype.DNSKEY)
        except KeyError:
            return None
    else:
        rdataset = value
    for rdata in rdataset:
        if rdata.algorithm == rrsig.algorithm and \
                key_id(rdata) == rrsig.key_tag:
            candidate_keys.append(rdata)
    return candidate_keys


def _is_rsa(algorithm):
    return algorithm in (RSAMD5, RSASHA1,
                         RSASHA1NSEC3SHA1, RSASHA256,
                         RSASHA512)


def _is_dsa(algorithm):
    return algorithm in (DSA, DSANSEC3SHA1)


def _is_ecdsa(algorithm):
    return algorithm in (ECDSAP256SHA256, ECDSAP384SHA384)


def _is_eddsa(algorithm):
    return algorithm in (ED25519, ED448)


def _is_gost(algorithm):
    return algorithm == ECCGOST


def _is_md5(algorithm):
    return algorithm == RSAMD5


def _is_sha1(algorithm):
    return algorithm in (DSA, RSASHA1,
                         DSANSEC3SHA1, RSASHA1NSEC3SHA1)


def _is_sha256(algorithm):
    return algorithm in (RSASHA256, ECDSAP256SHA256)


def _is_sha384(algorithm):
    return algorithm == ECDSAP384SHA384


def _is_sha512(algorithm):
    return algorithm == RSASHA512

class _IdentityHasher:
    def __init__(self):
        self.value = b''
    def update(self, s):
        self.value += s

def _make_hash(algorithm):
    if _is_md5(algorithm):
        return MD5.new()
    if _is_sha1(algorithm):
        return SHA1.new()
    if _is_sha256(algorithm):
        return SHA256.new()
    if _is_sha384(algorithm):
        return SHA384.new()
    if _is_sha512(algorithm):
        return SHA512.new()
    if _is_eddsa(algorithm):
        return _IdentityHasher()

    raise ValidationFailure('unknown hash for algorithm %u' % algorithm)


def _validate_rrsig(rrset, rrsig, keys, origin=None, now=None):
    """Validate an RRset against a single signature rdata

    :param rrset: The RRset to validate
    :type rrset: :py:data:`dns.rrset.RRset` or
    (:py:data:`dns.name.Name`, :py:data:`dns.rdataset.Rdataset`)
    :param rrsig: Signature to validate
    :type rrsig: :py:data:`dns.rdata.Rdata`
    :param keys: Key dictionary, used to find the DNSKEY associated
    with a given name.  The dictionary is keyed by a
    :py:data:`dns.name.Name`, and has :py:data:`dns.node.Node` or
    :py:data:`dns.rdataset.Rdataset` values.
    :type keys: dictionary
    :param origin: Origin to use for relative name, defaults to None
    :type origin: :py:data:`dns.name.Name`, optional
    :param now: time to use when validating the signatures, in seconds
    since the UNIX epoch, defaults to current time
    :type now: integer, optional
    :raises ValidationFailure: RRSig expired
    :raises ValidationFailure: RRSig not yet valid
    :raises ValidationFailure: Invalid public key
    :raises ValidationFailure: Invalid ECDSA key
    :raises ValidationFailure: Unknown algorithm
    :raises ValueError: Generic Value Error
    :raises ValidationFailure: Verify failure
    :raises UnsupportedAlgorithm: Algorithm isn't supported by dnspython
    :return: none
    :rtype: none

    .. todo:: Fill in missing infos

    """

    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)

    candidate_keys = _find_candidate_keys(keys, rrsig)
    if candidate_keys is None:
        raise ValidationFailure('unknown key')

    for candidate_key in candidate_keys:
        # For convenience, allow the rrset to be specified as a (name,
        # rdataset) tuple as well as a proper rrset
        if isinstance(rrset, tuple):
            rrname = rrset[0]
            rdataset = rrset[1]
        else:
            rrname = rrset.name
            rdataset = rrset

        if now is None:
            now = time.time()
        if rrsig.expiration < now:
            raise ValidationFailure('expired')
        if rrsig.inception > now:
            raise ValidationFailure('not yet valid')

        if _is_rsa(rrsig.algorithm):
            keyptr = candidate_key.key
            (bytes_,) = struct.unpack('!B', keyptr[0:1])
            keyptr = keyptr[1:]
            if bytes_ == 0:
                (bytes_,) = struct.unpack('!H', keyptr[0:2])
                keyptr = keyptr[2:]
            rsa_e = keyptr[0:bytes_]
            rsa_n = keyptr[bytes_:]
            try:
                pubkey = CryptoRSA.construct(
                    (number.bytes_to_long(rsa_n),
                     number.bytes_to_long(rsa_e)))
            except ValueError:
                raise ValidationFailure('invalid public key')
            sig = rrsig.signature
        elif _is_dsa(rrsig.algorithm):
            keyptr = candidate_key.key
            (t,) = struct.unpack('!B', keyptr[0:1])
            keyptr = keyptr[1:]
            octets = 64 + t * 8
            dsa_q = keyptr[0:20]
            keyptr = keyptr[20:]
            dsa_p = keyptr[0:octets]
            keyptr = keyptr[octets:]
            dsa_g = keyptr[0:octets]
            keyptr = keyptr[octets:]
            dsa_y = keyptr[0:octets]
            pubkey = CryptoDSA.construct(
                (number.bytes_to_long(dsa_y),
                 number.bytes_to_long(dsa_g),
                 number.bytes_to_long(dsa_p),
                 number.bytes_to_long(dsa_q)))
            sig = rrsig.signature[1:]
        elif _is_ecdsa(rrsig.algorithm):
            keyptr = candidate_key.key
            if rrsig.algorithm == ECDSAP256SHA256:
                curve = 'secp256r1'
                octets = 32
            else:
                curve = 'secp384r1'
                octets = 48
            ecdsa_x = keyptr[0:octets]
            ecdsa_y = keyptr[octets:octets * 2]
            pubkey = CryptoECC.construct(
                curve=curve,
                point_x=number.bytes_to_long(ecdsa_x),
                point_y=number.bytes_to_long(ecdsa_y))
            sig = rrsig.signature

        elif _is_eddsa(rrsig.algorithm):
            keyptr = candidate_key.key
            if not (_have_ecpy and sys.version_info >= (3, 6)):
                raise ImportError('DNSSEC validation for algorithm %u requires ecpy library and Python 3.6 or newer' % rrsig.algorithm)
            if rrsig.algorithm == ED25519:
                curve = 'Ed25519'
            else:
                curve = 'Ed448'
            point = Curve.get_curve(curve).decode_point(keyptr)
            pubkey = ECPublicKey(point)
            sig = rrsig.signature
        elif _is_gost(rrsig.algorithm):
            raise UnsupportedAlgorithm(
                'algorithm "%s" not supported by dnspython' % algorithm_to_text(rrsig.algorithm))
        else:
            raise ValidationFailure('unknown algorithm %u' % rrsig.algorithm)

        hash = _make_hash(rrsig.algorithm)
        hash.update(_to_rdata(rrsig, origin)[:18])
        hash.update(rrsig.signer.to_digestable(origin))

        if rrsig.labels < len(rrname) - 1:
            suffix = rrname.split(rrsig.labels + 1)[1]
            rrname = dns.name.from_text('*', suffix)
        rrnamebuf = rrname.to_digestable(origin)
        rrfixed = struct.pack('!HHI', rdataset.rdtype, rdataset.rdclass,
                              rrsig.original_ttl)
        rrlist = sorted(rdataset)
        for rr in rrlist:
            hash.update(rrnamebuf)
            hash.update(rrfixed)
            rrdata = rr.to_digestable(origin)
            rrlen = struct.pack('!H', len(rrdata))
            hash.update(rrlen)
            hash.update(rrdata)

        try:
            if _is_rsa(rrsig.algorithm):
                verifier = pkcs1_15.new(pubkey)
                # will raise ValueError if verify fails:
                verifier.verify(hash, sig)
            elif _is_dsa(rrsig.algorithm) or _is_ecdsa(rrsig.algorithm):
                verifier = DSS.new(pubkey, 'fips-186-3')
                verifier.verify(hash, sig)
            elif _is_eddsa(rrsig.algorithm):
                if rrsig.algorithm == ED25519:
                    verifier = EDDSA(hashlib.sha512)
                else:
                    verifier = EDDSA(hashlib.shake_256, 114)
                if not verifier.verify(hash.value, sig, pubkey):
                    raise ValueError
            else:
                # Raise here for code clarity; this won't actually ever happen
                # since if the algorithm is really unknown we'd already have
                # raised an exception above
                raise ValidationFailure('unknown algorithm %u' % rrsig.algorithm)
            # If we got here, we successfully verified so we can return without error
            return
        except ValueError:
            # this happens on an individual validation failure
            continue
    # nothing verified -- raise failure:
    raise ValidationFailure('verify failure')


def _validate(rrset, rrsigset, keys, origin=None, now=None):
    """Validate an RRset.

    :param rrset: RRset to validate
    :type rrset: :py:data:`dns.rrset.RRset` or
    (:py:data:`dns.name.Name`, :py:data:`dns.rdataset.Rdataset`) tuple
    :param rrsigset: Signature RRset to be validated
    :type rrsigset: :py:data`dns.rrset.RRset` or
    (:py:data:`dns.name.Name`, :py:data:`dns.rdataset.Rdataset`) tuple
    :param keys: Key dictionary, used to find the DNSKEY associated
    with a given name.  The dictionary is keyed by a
    :py:data:`dns.name.Name`, and has :py:data:`dns.node.Node` or
    :py:data:`dns.rdataset.Rdataset` values.
    :type keys: dictionary
    :param origin: Origin to use for relative name, defaults to None
    :type origin: :py:data:`dns.name.Name`, optional
    :param now: time to use when validating the signatures, in seconds
    since the UNIX epoch, defaults to current time
    :type now: integer, optional
    :raises ValidationFailure: Owner names do not match
    :raises ValidationFailure: No RRSIGs validated
    :raises UnsupportedAlgorithm: Algorithm isn't supported by dnspython

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
        try:
            _validate_rrsig(rrset, rrsig, keys, origin, now)
            return
        except ValidationFailure:
            pass
    raise ValidationFailure("no RRSIGs validated")


def _need_pycrypto(*args, **kwargs):
    raise ImportError("DNSSEC validation requires pycryptodome/pycryptodomex")


try:
    try:
        # test we're using pycryptodome, not pycrypto (which misses SHA1 for example)
        from Crypto.Hash import MD5, SHA1, SHA256, SHA384, SHA512
        from Crypto.PublicKey import RSA as CryptoRSA, DSA as CryptoDSA
        from Crypto.PublicKey import ECC as CryptoECC
        from Crypto.Signature import pkcs1_15, DSS
        from Crypto.Util import number
    except ImportError:
        from Cryptodome.Hash import MD5, SHA1, SHA256, SHA384, SHA512
        from Cryptodome.PublicKey import RSA as CryptoRSA, DSA as CryptoDSA
        from Cryptodome.PublicKey import ECC as CryptoECC
        from Cryptodome.Signature import pkcs1_15, DSS
        from Cryptodome.Util import number
except ImportError:
    validate = _need_pycrypto
    validate_rrsig = _need_pycrypto
    _have_pycrypto = False
else:
    validate = _validate
    validate_rrsig = _validate_rrsig
    _have_pycrypto = True

    try:
        from ecpy.curves import Curve, Point
        from ecpy.keys import ECPublicKey
        from ecpy.eddsa import EDDSA
    except ImportError:
        _have_ecpy = False
    else:
        _have_ecpy = True
