"""Create sample DNSSEC private JWK files."""

import dns.name
from dns.dnssectypes import Algorithm
from dns.dnssecalgs.serialization import Key
from dns.dnssecalgs import get_algorithm_cls

for algorithm in [Algorithm.MLDSA44]:
    private_cls = get_algorithm_cls(algorithm)

    private_key = private_cls.generate()
    dnskey = private_key.public_key().to_dnskey()

    key = Key(
        name=dns.name.from_text("example.com"),
        private=private_key,
        public=private_key.public_key(),
        dnskey=dnskey,
    )

    key.to_jwk_file(key.get_bind_private_key_filename().with_suffix(".json"))
    key.to_bind(".")

    print(key.get_bind_private_key_filename().name)
