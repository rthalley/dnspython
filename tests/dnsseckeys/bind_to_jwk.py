"""Synchronize DNSSEC private keys with their corresponding JWK files."""

from dns.dnssecalgs.serialization import Key
from pathlib import Path

for private_key_file in Path(".").glob("K*.private"):
    key_from_bind = Key.from_bind(private_key_file)
    key_from_bind.to_jwk_file(private_key_file.with_suffix(".json"))
