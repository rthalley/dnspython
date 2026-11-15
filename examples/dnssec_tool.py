import sys
from pathlib import Path
from typing import Annotated

import typer

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.zone
from dns.dnssecalgs import algorithms
from dns.dnssecalgs.base import GenericPrivateKey
from dns.dnssecalgs.serialization import Key
from dns.dnssectypes import Algorithm, DSDigest
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.NSEC3PARAM import NSEC3PARAM

name_to_cls = {a.name.upper(): cls for ((a, _), cls) in algorithms.items()}

app = typer.Typer(name="DNSSEC Toolbox")


@app.command(name="sign-zone")
def sign_zone(
    zonefile: Path,
    keys: list[Path],
    origin: str | None = None,
    lifetime: int | None = 3600,
    output: Path | None = None,
    nsec3: bool = False,
) -> None:
    """Sign a DNS zone with the provided KSK and ZSK keys."""

    zone = dns.zone.from_file(zonefile, origin=origin, relativize=False)
    if zone is None:
        raise ValueError(f"Failed to load zone from file {zonefile}")

    signing_keys: list[tuple[GenericPrivateKey, DNSKEY]] = []

    for key_file in keys:
        key = Key.from_jwk_file(key_file)
        if key.private is None:
            raise ValueError(f"Key {key.name} does not have a private key")
        if key.name != zone.origin:
            raise ValueError(
                f"Key name {key.name} does not match zone origin {zone.origin}"
            )
        signing_keys.append((key.private, key.dnskey))

    if not signing_keys:
        raise ValueError("No keys provided for signing")

    with zone.writer() as txn:
        dns.dnssec.sign_zone(
            zone=zone,
            txn=txn,
            keys=signing_keys,
            lifetime=lifetime,
            nsec3=(
                NSEC3PARAM(dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, 1, 0, 0, b"")
                if nsec3
                else None
            ),
        )

    zone.to_file(
        output or sys.stdout, relativize=False, sorted=True, want_comments=True
    )


@app.command(name="bind-to-jwk")
def convert_bind_to_jwk(keyfile: Path) -> None:
    """Convert a BIND-style key to a JWK."""

    if keyfile.suffix == ".key":
        with open(keyfile, "rb") as fp:
            keydata = fp.read()
        rrsets = dns.zonefile.read_rrsets(keydata, rdclass=None, default_ttl=0)
        if len(rrsets) != 1:
            raise ValueError(f"Expected exactly one RRset in key file {keyfile}")
        key = Key.from_dnskey(rrsets[0].name, rrsets[0].to_rdataset()[0])
    else:
        key = Key.from_bind(keyfile)
    key.to_jwk_file(keyfile.with_suffix(".json"), public_only=key.private is None)

    print(f"Converted {keyfile} to {keyfile.with_suffix('.json')}")


@app.command(name="jwk-to-bind")
def convert_jwk_to_bind(keyfile: Path) -> None:
    """Convert a JWK to a BIND-style key."""

    key = Key.from_jwk_file(keyfile)

    if key.private is not None:
        output_filename = key.to_bind(keyfile.parent)
        print(
            f"Converted {keyfile} to {output_filename} and {output_filename.with_suffix('.key')}"
        )
    else:
        output_filename = key.to_bind(keyfile.parent, public_only=True)
        print(f"Converted {keyfile} to {output_filename}")


@app.command(name="jwk-to-dnskey")
def convert_jwk_to_dnskey(keyfile: Path, cdnskey: bool = False) -> None:
    """Convert a JWK to a DNSKEY/CDNSKEY record."""

    key = Key.from_jwk_file(keyfile)

    if cdnskey:
        rdataset = dns.rdataset.from_rdata(0, key.cdnskey)
    else:
        rdataset = dns.rdataset.from_rdata(0, key.dnskey)

    print(
        rdataset.to_text(name=key.name, style=dns.rdataset.RdatasetStyle(omit_ttl=True))
    )


@app.command(name="jwk-to-ds")
def convert_jwk_to_ds(
    keyfile: Path,
    algorithm: Annotated[
        DSDigest,
        typer.Argument(parser=DSDigest.from_text),
    ] = DSDigest.SHA256.name,
    cds: bool = False,
) -> None:
    """Convert a JWK to a DS/CDS record."""

    key = Key.from_jwk_file(keyfile)

    if cds:
        rdataset = dns.rdataset.from_rdata(0, key.to_cds(algorithm))
    else:
        rdataset = dns.rdataset.from_rdata(0, key.to_ds(algorithm))

    print(
        rdataset.to_text(name=key.name, style=dns.rdataset.RdatasetStyle(omit_ttl=True))
    )


@app.command(name="generate-key")
def generate_key(
    name: Annotated[dns.name.Name, typer.Argument(parser=dns.name.from_text)],
    algorithm: Annotated[Algorithm, typer.Argument(parser=Algorithm.from_text)],
    size: int | None = None,
    ksk: bool = False,
    output: Path | None = None,
) -> None:
    """Generate a private key and output it as a JWK."""

    if (private_cls := algorithms.get((algorithm, None))) is None:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    match algorithm:
        case (
            Algorithm.RSAMD5
            | Algorithm.RSASHA1
            | Algorithm.RSASHA1NSEC3SHA1
            | Algorithm.RSASHA256
            | Algorithm.RSASHA512
        ):
            if not size:
                raise ValueError("Key size must be specified for RSA algorithms")
            private_key = private_cls.generate(key_size=size)
        case Algorithm.DSA | Algorithm.DSANSEC3SHA1:
            if not size:
                raise ValueError("Key size must be specified for DSA algorithms")
            private_key = private_cls.generate(key_size=size)
        case _:
            private_key = private_cls.generate()

    flags = dns.dnssec.Flag.ZONE
    if ksk:
        flags |= dns.dnssec.Flag.SEP

    key = Key(
        name=name,
        private=private_key,
        public=private_key.public_key(),
        dnskey=private_key.public_key().to_dnskey(flags=flags),
    )

    key.to_jwk_file(output or sys.stdout)


if __name__ == "__main__":
    app()
