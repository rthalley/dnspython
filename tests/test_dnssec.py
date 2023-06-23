# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2011 Nominum, Inc.
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

from datetime import datetime, timedelta, timezone
from typing import Any

import functools
import unittest

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.CDNSKEY
import dns.rdtypes.ANY.CDS
import dns.rdtypes.ANY.DNSKEY
import dns.rdtypes.ANY.DS
import dns.rrset
import dns.zone

from dns.rdtypes.dnskeybase import Flag

from .keys import test_dnskeys

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
except ImportError:
    pass  # Cryptography ImportError already handled in dns.dnssec

# pylint: disable=line-too-long

abs_dnspython_org = dns.name.from_text("dnspython.org")

abs_keys = {
    abs_dnspython_org: dns.rrset.from_text(
        "dnspython.org.",
        3600,
        "IN",
        "DNSKEY",
        "257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ"
        " XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z"
        " SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R"
        " KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce"
        " iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45"
        " NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=",
        "256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58"
        " LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP"
        " NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF",
    )
}

abs_keys_duplicate_keytag = {
    abs_dnspython_org: dns.rrset.from_text(
        "dnspython.org.",
        3600,
        "IN",
        "DNSKEY",
        "257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ"
        " XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z"
        " SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R"
        " KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce"
        " iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45"
        " NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=",
        "256 3 5 AwEAAdSSg++++THIS/IS/NOT/THE/CORRECT/KEY++++++++++++++++"
        " ++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
        " ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ AaOSydAF",
        "256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58"
        " LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP"
        " NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF",
    )
}

rel_keys = {
    dns.name.empty: dns.rrset.from_text(
        "@",
        3600,
        "IN",
        "DNSKEY",
        "257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ"
        " XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z"
        " SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R"
        " KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce"
        " iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45"
        " NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=",
        "256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58"
        " LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP"
        " NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF",
    )
}

when = 1290250287

abs_soa = dns.rrset.from_text(
    "dnspython.org.",
    3600,
    "IN",
    "SOA",
    "howl.dnspython.org. hostmaster.dnspython.org. 2010020047 3600 1800 604800 3600",
)

abs_other_soa = dns.rrset.from_text(
    "dnspython.org.",
    3600,
    "IN",
    "SOA",
    "foo.dnspython.org. hostmaster.dnspython.org. 2010020047 3600 1800 604800 3600",
)

abs_soa_rrsig = dns.rrset.from_text(
    "dnspython.org.",
    3600,
    "IN",
    "RRSIG",
    "SOA 5 2 3600 20101127004331 20101119213831 61695 dnspython.org."
    " sDUlltRlFTQw5ITFxOXW3TgmrHeMeNpdqcZ4EXxM9FHhIlte6V9YCnDw"
    " t6dvM9jAXdIEi03l9H/RAd9xNNW6gvGMHsBGzpvvqFQxIBR2PoiZA1mX"
    " /SWHZFdbt4xjYTtXqpyYvrMK0Dt7bUYPadyhPFCJ1B+I8Zi7B5WJEOd0 8vs=",
)

rel_soa = dns.rrset.from_text(
    "@", 3600, "IN", "SOA", "howl hostmaster 2010020047 3600 1800 604800 3600"
)

rel_other_soa = dns.rrset.from_text(
    "@", 3600, "IN", "SOA", "foo hostmaster 2010020047 3600 1800 604800 3600"
)

rel_soa_rrsig = dns.rrset.from_text(
    "@",
    3600,
    "IN",
    "RRSIG",
    "SOA 5 2 3600 20101127004331 20101119213831 61695 @"
    " sDUlltRlFTQw5ITFxOXW3TgmrHeMeNpdqcZ4EXxM9FHhIlte6V9YCnDw"
    " t6dvM9jAXdIEi03l9H/RAd9xNNW6gvGMHsBGzpvvqFQxIBR2PoiZA1mX"
    " /SWHZFdbt4xjYTtXqpyYvrMK0Dt7bUYPadyhPFCJ1B+I8Zi7B5WJEOd0 8vs=",
)

sep_key = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.DNSKEY,
    "257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ"
    " XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z"
    " SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R"
    " KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce"
    " iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45"
    " NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=",
)

good_ds = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.DS,
    "57349 5 2 53A79A3E7488AB44FFC56B2D1109F0699D1796DD977E72108B841F96 E47D7013",
)

good_cds = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.CDS,
    "57349 5 2 53A79A3E7488AB44FFC56B2D1109F0699D1796DD977E72108B841F96 E47D7013",
)

when2 = 1290425644

abs_example = dns.name.from_text("example")

abs_dsa_keys = {
    abs_example: dns.rrset.from_text(
        "example.",
        86400,
        "IN",
        "DNSKEY",
        "257 3 3 CI3nCqyJsiCJHTjrNsJOT4RaszetzcJPYuoH3F9ZTVt3KJXncCVR3bwn"
        " 1w0iavKljb9hDlAYSfHbFCp4ic/rvg4p1L8vh5s8ToMjqDNl40A0hUGQ"
        " Ybx5hsECyK+qHoajilUX1phYSAD8d9WAGO3fDWzUPBuzR7o85NiZCDxz"
        " yXuNVfni0uhj9n1KYhEO5yAbbruDGN89wIZcxMKuQsdUY2GYD93ssnBv"
        " a55W6XRABYWayKZ90WkRVODLVYLSn53Pj/wwxGH+XdhIAZJXimrZL4yl"
        " My7rtBsLMqq8Ihs4Tows7LqYwY7cp6y/50tw6pj8tFqMYcPUjKZV36l1"
        " M/2t5BVg3i7IK61Aidt6aoC3TDJtzAxg3ZxfjZWJfhHjMJqzQIfbW5b9"
        " q1mjFsW5EUv39RaNnX+3JWPRLyDqD4pIwDyqfutMsdk/Py3paHn82FGp"
        " CaOg+nicqZ9TiMZURN/XXy5JoXUNQ3RNvbHCUiPUe18KUkY6mTfnyHld"
        " 1l9YCWmzXQVClkx/hOYxjJ4j8Ife58+Obu5X",
        "256 3 3 CJE1yb9YRQiw5d2xZrMUMR+cGCTt1bp1KDCefmYKmS+Z1+q9f42ETVhx"
        " JRiQwXclYwmxborzIkSZegTNYIV6mrYwbNB27Q44c3UGcspb3PiOw5TC"
        " jNPRYEcdwGvDZ2wWy+vkSV/S9tHXY8O6ODiE6abZJDDg/RnITyi+eoDL"
        " R3KZ5n/V1f1T1b90rrV6EewhBGQJpQGDogaXb2oHww9Tm6NfXyo7SoMM"
        " pbwbzOckXv+GxRPJIQNSF4D4A9E8XCksuzVVdE/0lr37+uoiAiPia38U"
        " 5W2QWe/FJAEPLjIp2eTzf0TrADc1pKP1wrA2ASpdzpm/aX3IB5RPp8Ew"
        " S9U72eBFZJAUwg635HxJVxH1maG6atzorR566E+e0OZSaxXS9o1o6QqN"
        " 3oPlYLGPORDiExilKfez3C/x/yioOupW9K5eKF0gmtaqrHX0oq9s67f/"
        " RIM2xVaKHgG9Vf2cgJIZkhv7sntujr+E4htnRmy9P9BxyFxsItYxPI6Z"
        " bzygHAZpGhlI/7ltEGlIwKxyTK3ZKBm67q7B",
    )
}

abs_dsa_soa = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "SOA",
    "ns1.example. hostmaster.example. 2 10800 3600 604800 86400",
)

abs_other_dsa_soa = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "SOA",
    "ns1.example. hostmaster.example. 2 10800 3600 604800 86401",
)

abs_dsa_soa_rrsig = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "RRSIG",
    "SOA 3 1 86400 20101129143231 20101122112731 42088 example."
    " CGul9SuBofsktunV8cJs4eRs6u+3NCS3yaPKvBbD+pB2C76OUXDZq9U=",
)

example_sep_key = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.DNSKEY,
    "257 3 3 CI3nCqyJsiCJHTjrNsJOT4RaszetzcJPYuoH3F9ZTVt3KJXncCVR3bwn"
    " 1w0iavKljb9hDlAYSfHbFCp4ic/rvg4p1L8vh5s8ToMjqDNl40A0hUGQ"
    " Ybx5hsECyK+qHoajilUX1phYSAD8d9WAGO3fDWzUPBuzR7o85NiZCDxz"
    " yXuNVfni0uhj9n1KYhEO5yAbbruDGN89wIZcxMKuQsdUY2GYD93ssnBv"
    " a55W6XRABYWayKZ90WkRVODLVYLSn53Pj/wwxGH+XdhIAZJXimrZL4yl"
    " My7rtBsLMqq8Ihs4Tows7LqYwY7cp6y/50tw6pj8tFqMYcPUjKZV36l1"
    " M/2t5BVg3i7IK61Aidt6aoC3TDJtzAxg3ZxfjZWJfhHjMJqzQIfbW5b9"
    " q1mjFsW5EUv39RaNnX+3JWPRLyDqD4pIwDyqfutMsdk/Py3paHn82FGp"
    " CaOg+nicqZ9TiMZURN/XXy5JoXUNQ3RNvbHCUiPUe18KUkY6mTfnyHld"
    " 1l9YCWmzXQVClkx/hOYxjJ4j8Ife58+Obu5X",
)

example_ds_sha1 = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.DS,
    "18673 3 1 71b71d4f3e11bbd71b4eff12cde69f7f9215bbe7",
)

example_ds_sha256 = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.DS,
    "18673 3 2 eb8344cbbf07c9d3d3d6c81d10c76653e28d8611a65e639ef8f716e4e4e5d913",
)

example_ds_sha384 = dns.rdata.from_text(
    dns.rdataclass.IN,
    dns.rdatatype.DS,
    "18673 3 4 61ab241025c5f88d2537be04dcfba96f952adaefe0b382ec"
    "bc4108c97b75768c9e99fd16caed2a09634c51e8089fb84f",
)

when3 = 1379801800

abs_ecdsa256_keys = {
    abs_example: dns.rrset.from_text(
        "example.",
        86400,
        "IN",
        "DNSKEY",
        "256 3 13 +3ss1sCpdARVA61DJigEsL/8quo2a8MszKtn2gkkfxgzFs8S2UHtpb4N"
        " fY+XFmNW+JK6MsCkI3jHYN8eEQUgMw==",
        "257 3 13 eJCEVH7AS3wnoaQpaNlAXH0W8wxymtT9P6P3qjN2ZCV641ED8pF7wZ5V"
        " yWfOpgTs6oaZevbJgehl/GaRPUgVyQ==",
    )
}

abs_ecdsa256_soa = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "SOA",
    "ns1.example. hostmaster.example. 4 10800 3600 604800 86400",
)

abs_other_ecdsa256_soa = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "SOA",
    "ns1.example. hostmaster.example. 2 10800 3600 604800 86401",
)

abs_ecdsa256_soa_rrsig = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "RRSIG",
    "SOA 13 1 86400 20130921221753 20130921221638 7460 example."
    " Sm09SOGz1ULB5D/duwdE2Zpn8bWbVBM77H6N1wPkc42LevvVO+kZEjpq"
    " 2nq4GOMJcih52667GIAbMrwmU5P2MQ==",
)

when4 = 1379804850

abs_ecdsa384_keys = {
    abs_example: dns.rrset.from_text(
        "example.",
        86400,
        "IN",
        "DNSKEY",
        "256 3 14 1bG8qWviKNXQX3BIuG6/T5jrP1FISiLW/8qGF6BsM9DQtWYhhZUA3Owr"
        " OAEiyHAhQwjkN2kTvWiAYoPN80Ii+5ff9/atzY4F9W50P4l75Dj9PYrL HN/hLUgWMNVc9pvA",
        "257 3 14 mSub2n0KRt6u2FaD5XJ3oQu0R4XvB/9vUJcyW6+oo0y+KzfQeTdkf1ro"
        " ZMVKoyWXW9zUKBYGJpMUIdbAxzrYi7f5HyZ3yDpBFz1hw9+o3CX+gtgb +RyhHfJDwwFXBid9",
    )
}

abs_ecdsa384_soa = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "SOA",
    "ns1.example. hostmaster.example. 2 10800 3600 604800 86400",
)

abs_other_ecdsa384_soa = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "SOA",
    "ns1.example. hostmaster.example. 2 10800 3600 604800 86401",
)

abs_ecdsa384_soa_rrsig = dns.rrset.from_text(
    "example.",
    86400,
    "IN",
    "RRSIG",
    "SOA 14 1 86400 20130929021229 20130921230729 63571 example."
    " CrnCu34EeeRz0fEhL9PLlwjpBKGYW8QjBjFQTwd+ViVLRAS8tNkcDwQE"
    " NhSV89NEjj7ze1a/JcCfcJ+/mZgnvH4NHLNg3Tf6KuLZsgs2I4kKQXEk 37oIHravPEOlGYNI",
)

abs_example_com = dns.name.from_text("example.com")

abs_ed25519_mx = dns.rrset.from_text(
    "example.com.", 3600, "IN", "MX", "10 mail.example.com."
)
abs_other_ed25519_mx = dns.rrset.from_text(
    "example.com.", 3600, "IN", "MX", "11 mail.example.com."
)
abs_ed25519_keys_1 = {
    abs_example_com: dns.rrset.from_text(
        "example.com",
        3600,
        "IN",
        "DNSKEY",
        "257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=",
    )
}
abs_ed25519_mx_rrsig_1 = dns.rrset.from_text(
    "example.com.",
    3600,
    "IN",
    "RRSIG",
    "MX 15 2 3600 1440021600 1438207200 3613 example.com."
    " oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeR"
    "AvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==",
)

abs_ed25519_keys_2 = {
    abs_example_com: dns.rrset.from_text(
        "example.com",
        3600,
        "IN",
        "DNSKEY",
        "257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=",
    )
}
abs_ed25519_mx_rrsig_2 = dns.rrset.from_text(
    "example.com.",
    3600,
    "IN",
    "RRSIG",
    "MX 15 2 3600 1440021600 1438207200 35217 example.com."
    " zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT4"
    "10QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg==",
)

abs_ed448_mx = abs_ed25519_mx
abs_other_ed448_mx = abs_other_ed25519_mx

abs_ed448_keys_1 = {
    abs_example_com: dns.rrset.from_text(
        "example.com",
        3600,
        "IN",
        "DNSKEY",
        "257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+"
        "G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA",
    )
}
abs_ed448_mx_rrsig_1 = dns.rrset.from_text(
    "example.com.",
    3600,
    "IN",
    "RRSIG",
    "MX 16 2 3600 1440021600 1438207200 9713 example.com."
    " 3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0amxWndkmnBZ6SKiwZSA"
    "xGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA",
)

abs_ed448_keys_2 = {
    abs_example_com: dns.rrset.from_text(
        "example.com",
        3600,
        "IN",
        "DNSKEY",
        "257 3 16 kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUur"
        "BRQc3tDjeMCJcVMRDmgcNLp5HlHAMy12VoISsA",
    )
}
abs_ed448_mx_rrsig_2 = dns.rrset.from_text(
    "example.com.",
    3600,
    "IN",
    "RRSIG",
    "MX 16 2 3600 1440021600 1438207200 38353 example.com."
    " E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4Sp8Syg1eI+lJ57CSnZqjJP41O/9l4m0A"
    "sQ4f7qI1gVnML8vWWiyW2KXhT9kuAICUSxv5OWbf81Rq7Yu60npabODB0QFPb/rkW3kUZmQ0YQUA",
)

when5 = 1440021600
when5_start = 1438207200

wildcard_keys = {
    abs_example_com: dns.rrset.from_text(
        "example.com",
        3600,
        "IN",
        "DNSKEY",
        "256 3 5 AwEAAecNZbwD2thg3kaRLVqCC7ASP/3F79ZIu7pCu8HvZZ6ZdinffnxT"
        " npNoVvavjouHKFYTtJyUZAfw3ZMJSsGvEerc7uh6Ex9TgvOJtWPGUtxB"
        " Nnni2u9Nk+5k6nJzMiS3sL3RLvrfZW5d2Bwbl9L5f9Ud+r2Dbm7EG3tY pMY5OE8f",
    )
}
wildcard_example_com = dns.name.from_text("*", abs_example_com)
wildcard_txt = dns.rrset.from_text("*.example.com.", 3600, "IN", "TXT", "foo")
wildcard_txt_rrsig = dns.rrset.from_text(
    "*.example.com.",
    3600,
    "IN",
    "RRSIG",
    "TXT 5 2 3600 20200707211255 20200630180755 42486 example.com."
    " qevJYhdAHq1VmehXQ5i+Epa32xs4zcd4qmb39pHa3GUKr1V504nxzdzQ"
    " gsT5mvDkRoY95+HAiysDON6DCDtZc69iBUIHWWuFo/OrcD2q/mWANG4x"
    " vyU28Pf0U1gN6Gd5iapKC0Ya12flKh//NQiNN2skOQ2MoF2MW2/MaAK2 HBc=",
)

wildcard_when = 1593541048


rsamd5_keys = {
    abs_example: dns.rrset.from_text(
        "example",
        3600,
        "in",
        "dnskey",
        "257 3 1 AwEAAewnoEWe+AVEnQzcZTwpl8K/QKuScYIX"
        " 9xHOhejAL1enMjE0j97Gq3XXJJPWF7eQQGHs"
        " 1De4Srv2UT0zRCLkH9r36lOR/ggANvthO/Ub"
        " Es0hlD3A58LumEPudgIDwEkxGvQAXMFTMw0x"
        " 1d/a82UtzmNoPVzFOl2r+OCXx9Jbdh/L;"
        " KSK; alg = RSAMD5; key id = 30239",
        "256 3 1 AwEAAb8OJM5YcqaYG0fenUdRlrhBQ6LuwCvr"
        " 5BRlrVbVzadSDBpq+yIiklfdGNBg3WZztDy1"
        " du62NWC/olMfc6uRe/SjqTa7IJ3MdEuZQXQw"
        " MedGdNSF73zbokx8wg7zBBr74xHczJcEpQhr"
        " ZLzwCDmIPu0yoVi3Yqdl4dm4vNBj9hAD;"
        " ZSK; alg = RSAMD5; key id = 62992",
    )
}

rsamd5_ns = dns.rrset.from_text(
    "example.", 3600, "in", "ns", "ns1.example.", "ns2.example."
)
rsamd5_ns_rrsig = dns.rrset.from_text(
    "example.",
    3600,
    "in",
    "rrsig",
    "NS 1 1 3600 20200825153103 20200726153103 62992 example."
    " YPv0WVqzQBDH45mFcYGo9psCVoMoeeHeAugh"
    " 9RZuO2NmdwfQ3mmiQm7WJ3AYnzYIozFGf7CL"
    " nwn3vN8/fjsfcQgEv5xfhFTSd4IoAzJJiZAa"
    " vrI4L5590C/+aXQ8tjRmbMTPiqoudaXvsevE jP2lTFg5DCruJyFq5dnAY5b90RY=",
)

rsamd5_when = 1595781671

rsasha512_keys = {
    abs_example: dns.rrset.from_text(
        "example",
        3600,
        "in",
        "dnskey",
        "256 3 10 AwEAAb2JvKjZ6l5qg2ab3qqUQhLGGjsiMIuQ"
        " 2zhaXJHdTntS+8LgUXo5yLFn7YF9YL1VX9V4"
        " 5ASGxUpz0u0chjWqBNtUO3Ymzas/vck9o21M"
        " 2Ce/LrpfYsqvJaLvGf/dozW9uSeMQq1mPKYG"
        " xo4uxyhZBhZewX8znXZySrAIozBPH3yp ;"
        " ZSK; alg = RSASHA512 ; key id = 5957",
        "257 3 10 AwEAAc7Lnoe+mHijJ8OOHgyJHKYantQGKx5t"
        " rIs267gOePyAL7cUt9HO1Sm3vABSGNsoHL6w"
        " 8/542SxGbT21osVISamtq7kUPTgDU9iKqCBq"
        " VdXEdzXYbhBKVoQkGPl4PflfbOgg/45xAiTi"
        " 7qOUERuRCPdKEkd4FW0tg6VfZmm7QjP1 ;"
        " KSK; alg = RSASHA512 ; key id = 53212",
    )
}

rsasha512_ns = dns.rrset.from_text(
    "example.", 3600, "in", "ns", "ns1.example.", "ns2.example."
)
rsasha512_ns_rrsig = dns.rrset.from_text(
    "example.",
    3600,
    "in",
    "rrsig",
    "NS 10 1 3600 20200825161255 20200726161255 5957 example."
    " P9A+1zYke7yIiKEnxFMm+UIW2CIwy2WDvbx6"
    " g8hHiI8qISe6oeKveFW23OSk9+VwFgBiOpeM"
    " ygzzFbckY7RkGbOr4TR8ogDRANt6LhV402Hu"
    " SXTV9hCLVFWU4PS+/fxxfOHCetsY5tWWSxZi"
    " zSHfgpGfsHWzQoAamag4XYDyykc=",
)

rsasha512_when = 1595783997


unknown_alg_keys = {
    abs_example: dns.rrset.from_text(
        "example", 3600, "in", "dnskey", "256 3 100 Ym9ndXM=", "257 3 100 Ym9ndXM="
    )
}

unknown_alg_ns_rrsig = dns.rrset.from_text(
    "example.",
    3600,
    "in",
    "rrsig",
    "NS 100 1 3600 20200825161255 20200726161255 16713 example."
    " P9A+1zYke7yIiKEnxFMm+UIW2CIwy2WDvbx6"
    " g8hHiI8qISe6oeKveFW23OSk9+VwFgBiOpeM"
    " ygzzFbckY7RkGbOr4TR8ogDRANt6LhV402Hu"
    " SXTV9hCLVFWU4PS+/fxxfOHCetsY5tWWSxZi"
    " zSHfgpGfsHWzQoAamag4XYDyykc=",
)

fake_gost_keys = {
    abs_example: dns.rrset.from_text(
        "example", 3600, "in", "dnskey", "256 3 12 Ym9ndXM=", "257 3 12 Ym9ndXM="
    )
}

fake_gost_ns_rrsig = dns.rrset.from_text(
    "example.",
    3600,
    "in",
    "rrsig",
    "NS 12 1 3600 20200825161255 20200726161255 16625 example."
    " P9A+1zYke7yIiKEnxFMm+UIW2CIwy2WDvbx6"
    " g8hHiI8qISe6oeKveFW23OSk9+VwFgBiOpeM"
    " ygzzFbckY7RkGbOr4TR8ogDRANt6LhV402Hu"
    " SXTV9hCLVFWU4PS+/fxxfOHCetsY5tWWSxZi zSHfgpGfsHWzQoAamag4XYDyykc=",
)

test_zone_sans_nsec = """
example. 3600 IN SOA foo.example. bar.example. 1 2 3 4 5
example. 3600 IN NS ns1.example.
example. 3600 IN NS ns2.example.
bar.foo.example. 3600 IN MX 0 blaz.foo.example.
ns1.example. 3600 IN A 10.0.0.1
ns2.example. 3600 IN A 10.0.0.2
sub.example. 3600 IN NS ns1.example.
sub.example. 3600 IN NS ns2.example.
sub.example. 3600 IN NS ns3.sub.example.
sub.example. 3600 IN DS 12345 13 2 0100D208742A23024DF3C8827DFF3EB3E25126E9B72850E99D6055E18913CB2F
sub.sub.example. 3600 IN NS ns3.sub.example.
ns3.sub.example. 3600 IN A 10.0.0.3
"""

test_zone_rrsigs = set(
    [
        ("example.", dns.rdatatype.DNSKEY),
        ("example.", dns.rdatatype.NS),
        ("example.", dns.rdatatype.NSEC),
        ("example.", dns.rdatatype.SOA),
        ("bar.foo.example.", dns.rdatatype.MX),
        ("bar.foo.example.", dns.rdatatype.NSEC),
        ("ns1.example.", dns.rdatatype.A),
        ("ns1.example.", dns.rdatatype.NSEC),
        ("ns2.example.", dns.rdatatype.A),
        ("ns2.example.", dns.rdatatype.NSEC),
        ("sub.example.", dns.rdatatype.DS),
        ("sub.example.", dns.rdatatype.NSEC),
    ]
)

test_zone_with_nsec = """
example. 3600 IN SOA foo.example. bar.example. 1 2 3 4 5
example. 3600 IN NS ns1.example.
example. 3600 IN NS ns2.example.
example. 5 IN NSEC bar.foo.example. NS NSEC SOA RRSIG
bar.foo.example. 3600 IN MX 0 blaz.foo.example.
bar.foo.example. 5 IN NSEC ns1.example. MX NSEC RRSIG
ns1.example. 3600 IN A 10.0.0.1
ns1.example. 5 IN NSEC ns2.example. A NSEC RRSIG
ns2.example. 3600 IN A 10.0.0.2
ns2.example. 5 IN NSEC sub.example. A NSEC RRSIG
sub.example. 3600 IN NS ns1.example.
sub.example. 3600 IN NS ns2.example.
sub.example. 3600 IN NS ns3.sub.example.
sub.example. 3600 IN DS 12345 13 2 0100D208742A23024DF3C8827DFF3EB3E25126E9B72850E99D6055E18913CB2F
sub.example. 5 IN NSEC example. DS NS NSEC RRSIG
sub.sub.example. 3600 IN NS ns3.sub.example.
ns3.sub.example. 3600 IN A 10.0.0.3
"""


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class DNSSECValidatorTestCase(unittest.TestCase):
    def testAbsoluteRSAMD5Good(self):  # type: () -> None
        dns.dnssec.validate(
            rsamd5_ns,
            rsamd5_ns_rrsig,
            rsamd5_keys,
            None,
            rsamd5_when,
            policy=dns.dnssec.allow_all_policy,
        )

    def testAbsoluteRSAMD5GoodDeniedByPolicy(self):  # type: () -> None
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                rsamd5_ns, rsamd5_ns_rrsig, rsamd5_keys, None, rsamd5_when
            )

    def testRSAMD5Keyid(self):
        self.assertEqual(dns.dnssec.key_id(rsamd5_keys[abs_example][0]), 30239)
        self.assertEqual(dns.dnssec.key_id(rsamd5_keys[abs_example][1]), 62992)

    def testAbsoluteRSAGood(self):  # type: () -> None
        dns.dnssec.validate(abs_soa, abs_soa_rrsig, abs_keys, None, when)

    def testDuplicateKeytag(self):  # type: () -> None
        dns.dnssec.validate(
            abs_soa, abs_soa_rrsig, abs_keys_duplicate_keytag, None, when
        )

    def testAbsoluteRSABad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(abs_other_soa, abs_soa_rrsig, abs_keys, None, when)

        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testRelativeRSAGood(self):  # type: () -> None
        dns.dnssec.validate(rel_soa, rel_soa_rrsig, rel_keys, abs_dnspython_org, when)
        # test the text conversion for origin too
        dns.dnssec.validate(rel_soa, rel_soa_rrsig, rel_keys, "dnspython.org", when)

    def testRelativeRSABad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(
                rel_other_soa, rel_soa_rrsig, rel_keys, abs_dnspython_org, when
            )

        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testAbsoluteDSAGood(self):  # type: () -> None
        dns.dnssec.validate(
            abs_dsa_soa,
            abs_dsa_soa_rrsig,
            abs_dsa_keys,
            None,
            when2,
            policy=dns.dnssec.allow_all_policy,
        )

    def testAbsoluteDSAGoodDeniedByPolicy(self):  # type: () -> None
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_dsa_soa, abs_dsa_soa_rrsig, abs_dsa_keys, None, when2
            )

    def testAbsoluteDSABad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(
                abs_other_dsa_soa,
                abs_dsa_soa_rrsig,
                abs_dsa_keys,
                None,
                when2,
                policy=dns.dnssec.allow_all_policy,
            )

        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testAbsoluteECDSA256Good(self):  # type: () -> None
        dns.dnssec.validate(
            abs_ecdsa256_soa, abs_ecdsa256_soa_rrsig, abs_ecdsa256_keys, None, when3
        )

    def testAbsoluteECDSA256Bad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(
                abs_other_ecdsa256_soa,
                abs_ecdsa256_soa_rrsig,
                abs_ecdsa256_keys,
                None,
                when3,
            )

        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testAbsoluteECDSA384Good(self):  # type: () -> None
        dns.dnssec.validate(
            abs_ecdsa384_soa, abs_ecdsa384_soa_rrsig, abs_ecdsa384_keys, None, when4
        )

    def testAbsoluteECDSA384Bad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(
                abs_other_ecdsa384_soa,
                abs_ecdsa384_soa_rrsig,
                abs_ecdsa384_keys,
                None,
                when4,
            )

        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testAbsoluteED25519Good(self):  # type: () -> None
        dns.dnssec.validate(
            abs_ed25519_mx, abs_ed25519_mx_rrsig_1, abs_ed25519_keys_1, None, when5
        )
        dns.dnssec.validate(
            abs_ed25519_mx, abs_ed25519_mx_rrsig_2, abs_ed25519_keys_2, None, when5
        )

    def testAbsoluteED25519Bad(self):  # type: () -> None
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_other_ed25519_mx,
                abs_ed25519_mx_rrsig_1,
                abs_ed25519_keys_1,
                None,
                when5,
            )
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_other_ed25519_mx,
                abs_ed25519_mx_rrsig_2,
                abs_ed25519_keys_2,
                None,
                when5,
            )

    def testAbsoluteED448Good(self):  # type: () -> None
        dns.dnssec.validate(
            abs_ed448_mx, abs_ed448_mx_rrsig_1, abs_ed448_keys_1, None, when5
        )
        dns.dnssec.validate(
            abs_ed448_mx, abs_ed448_mx_rrsig_2, abs_ed448_keys_2, None, when5
        )

    def testAbsoluteED448Bad(self):  # type: () -> None
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_other_ed448_mx, abs_ed448_mx_rrsig_1, abs_ed448_keys_1, None, when5
            )
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_other_ed448_mx, abs_ed448_mx_rrsig_2, abs_ed448_keys_2, None, when5
            )

    def testAbsoluteRSASHA512Good(self):
        dns.dnssec.validate(
            rsasha512_ns, rsasha512_ns_rrsig, rsasha512_keys, None, rsasha512_when
        )

    def testWildcardGoodAndBad(self):
        dns.dnssec.validate(
            wildcard_txt, wildcard_txt_rrsig, wildcard_keys, None, wildcard_when
        )

        def clone_rrset(rrset, name):
            return dns.rrset.from_rdata(name, rrset.ttl, rrset[0])

        a_name = dns.name.from_text("a.example.com")
        a_txt = clone_rrset(wildcard_txt, a_name)
        a_txt_rrsig = clone_rrset(wildcard_txt_rrsig, a_name)
        dns.dnssec.validate(a_txt, a_txt_rrsig, wildcard_keys, None, wildcard_when)

        abc_name = dns.name.from_text("a.b.c.example.com")
        abc_txt = clone_rrset(wildcard_txt, abc_name)
        abc_txt_rrsig = clone_rrset(wildcard_txt_rrsig, abc_name)
        dns.dnssec.validate(abc_txt, abc_txt_rrsig, wildcard_keys, None, wildcard_when)

        com_name = dns.name.from_text("com.")
        com_txt = clone_rrset(wildcard_txt, com_name)
        com_txt_rrsig = clone_rrset(wildcard_txt_rrsig, abc_name)
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate_rrsig(
                com_txt, com_txt_rrsig[0], wildcard_keys, None, wildcard_when
            )

        # check some bogus label lengths
        a_name = dns.name.from_text("a.example.com")
        a_txt = clone_rrset(wildcard_txt, a_name)
        a_txt_rrsig = clone_rrset(wildcard_txt_rrsig, a_name)
        bad_rrsig = a_txt_rrsig[0].replace(labels=99)
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate_rrsig(
                a_txt, bad_rrsig, wildcard_keys, None, wildcard_when
            )
        bad_rrsig = a_txt_rrsig[0].replace(labels=3)
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate_rrsig(
                a_txt, bad_rrsig, wildcard_keys, None, wildcard_when
            )
        bad_rrsig = a_txt_rrsig[0].replace(labels=1)
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate_rrsig(
                a_txt, bad_rrsig, wildcard_keys, None, wildcard_when
            )

    def testAlternateParameterFormats(self):  # type: () -> None
        # Pass rrset and rrsigset as (name, rdataset) tuples, not rrsets
        rrset = (abs_soa.name, abs_soa.to_rdataset())
        rrsigset = (abs_soa_rrsig.name, abs_soa_rrsig.to_rdataset())
        dns.dnssec.validate(rrset, rrsigset, abs_keys, None, when)

        # Pass keys as a name->node dict, not a name->rrset dict
        keys = {}
        for name, key_rrset in abs_keys.items():
            keys[name] = dns.node.Node()
            keys[name].rdatasets.append(key_rrset.to_rdataset())
        dns.dnssec.validate(abs_soa, abs_soa_rrsig, keys, None, when)
        # test key not found.
        keys = {}
        for name, key_rrset in abs_keys.items():
            keys[name] = dns.node.Node()
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(abs_soa, abs_soa_rrsig, keys, None, when)

        # Pass origin as a string, not a name.
        dns.dnssec.validate(rel_soa, rel_soa_rrsig, rel_keys, "dnspython.org", when)
        dns.dnssec.validate_rrsig(
            rel_soa, rel_soa_rrsig[0], rel_keys, "dnspython.org", when
        )

    def testAbsoluteKeyNotFound(self):
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(abs_ed448_mx, abs_ed448_mx_rrsig_1, {}, None, when5)

    def testTimeBounds(self):
        # not yet valid
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_ed448_mx,
                abs_ed448_mx_rrsig_1,
                abs_ed448_keys_1,
                None,
                when5_start - 1,
            )
        # expired
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_ed448_mx, abs_ed448_mx_rrsig_1, abs_ed448_keys_1, None, when5 + 1
            )
        # expired using the current time (to test the "get the time" code
        # path)
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                abs_ed448_mx, abs_ed448_mx_rrsig_1, abs_ed448_keys_1, None
            )

    def testOwnerNameMismatch(self):
        bogus = dns.name.from_text("example.bogus")
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                (bogus, abs_ed448_mx),
                abs_ed448_mx_rrsig_1,
                abs_ed448_keys_1,
                None,
                when5 + 1,
            )

    def testGOSTNotSupported(self):
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                rsasha512_ns, fake_gost_ns_rrsig, fake_gost_keys, None, rsasha512_when
            )

    def testUnknownAlgorithm(self):
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(
                rsasha512_ns,
                unknown_alg_ns_rrsig,
                unknown_alg_keys,
                None,
                rsasha512_when,
            )


class DNSSECMiscTestCase(unittest.TestCase):
    def testDigestToBig(self):
        with self.assertRaises(ValueError):
            dns.dnssec.DSDigest.make(256)

    def testNSEC3HashTooBig(self):
        with self.assertRaises(ValueError):
            dns.dnssec.NSEC3Hash.make(256)

    def testIsNotGOST(self):
        self.assertTrue(dns.dnssec._is_gost(dns.dnssec.Algorithm.ECCGOST))

    def testUnknownHash(self):
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec._make_hash(100)

    def testToTimestamp(self):
        REFERENCE_TIMESTAMP = 441812220

        ts = dns.dnssec.to_timestamp(
            datetime(year=1984, month=1, day=1, hour=13, minute=37, tzinfo=timezone.utc)
        )
        self.assertEqual(ts, REFERENCE_TIMESTAMP)

        ts = dns.dnssec.to_timestamp("19840101133700")
        self.assertEqual(ts, REFERENCE_TIMESTAMP)

        ts = dns.dnssec.to_timestamp(441812220.0)
        self.assertEqual(ts, REFERENCE_TIMESTAMP)

        ts = dns.dnssec.to_timestamp(441812220)
        self.assertEqual(ts, REFERENCE_TIMESTAMP)

    def do_test_sign_zone(self, relativize):
        zone = dns.zone.from_text(
            test_zone_sans_nsec, "example.", relativize=relativize
        )

        algorithm = dns.dnssec.Algorithm.ED25519
        lifetime = 3600

        ksk_private_key = ed25519.Ed25519PrivateKey.generate()
        ksk_dnskey = dns.dnssec.make_dnskey(
            public_key=ksk_private_key.public_key(),
            algorithm=algorithm,
            flags=Flag.ZONE | Flag.SEP,
        )

        zsk_private_key = ed25519.Ed25519PrivateKey.generate()
        zsk_dnskey = dns.dnssec.make_dnskey(
            public_key=zsk_private_key.public_key(),
            algorithm=algorithm,
            flags=Flag.ZONE,
        )

        keys = [(ksk_private_key, ksk_dnskey), (zsk_private_key, zsk_dnskey)]

        with zone.writer() as txn:
            dns.dnssec.sign_zone(
                zone=zone,
                txn=txn,
                keys=keys,
                lifetime=lifetime,
            )

        print(zone.to_text())
        rrsigs = set(
            [
                (str(name.derelativize(zone.origin)), rdataset.covers)
                for (name, rdataset) in zone.iterate_rdatasets()
                if rdataset.rdtype == dns.rdatatype.RRSIG
            ]
        )
        self.assertEqual(rrsigs, test_zone_rrsigs)

        signers = set(
            [
                (
                    str(name.derelativize(zone.origin)),
                    rdataset.covers,
                    rdataset[0].key_tag,
                )
                for (name, rdataset) in zone.iterate_rdatasets()
                if rdataset.rdtype == dns.rdatatype.RRSIG
            ]
        )
        for name, covers, key_tag in signers:
            if covers in [
                dns.rdatatype.DNSKEY,
                dns.rdatatype.CDNSKEY,
                dns.rdatatype.CDS,
            ]:
                self.assertEqual(key_tag, dns.dnssec.key_id(ksk_dnskey))
            else:
                self.assertEqual(key_tag, dns.dnssec.key_id(zsk_dnskey))

    def test_sign_zone_absolute(self):
        self.do_test_sign_zone(False)

    def test_sign_zone_relative(self):
        self.do_test_sign_zone(True)

    def test_sign_zone_nsec_null_signer(self):
        def rrset_signer(
            txn: dns.transaction.Transaction,
            rrset: dns.rrset.RRset,
        ) -> None:
            pass

        zone1 = dns.zone.from_text(test_zone_sans_nsec, "example.", relativize=False)
        dns.dnssec.sign_zone(zone1, rrset_signer=rrset_signer)

        zone2 = dns.zone.from_text(test_zone_with_nsec, "example.", relativize=False)
        self.assertEqual(zone1.to_text(), zone2.to_text())


class DNSSECMakeDSTestCase(unittest.TestCase):
    def testMnemonicParser(self):
        good_ds_mnemonic = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.DS,
            "57349 RSASHA1 2 53A79A3E7488AB44FFC56B2D1109F0699D1796DD977E72108B841F96"
            " E47D7013",
        )
        self.assertEqual(good_ds, good_ds_mnemonic)

    def testMakeExampleSHA1DS(self):  # type: () -> None
        algorithm: Any
        for algorithm in ("SHA1", "sha1", dns.dnssec.DSDigest.SHA1):
            ds = dns.dnssec.make_ds(
                abs_example,
                example_sep_key,
                algorithm,
                policy=dns.dnssec.allow_all_policy,
            )
            self.assertEqual(ds, example_ds_sha1)
            ds = dns.dnssec.make_ds(
                "example.",
                example_sep_key,
                algorithm,
                policy=dns.dnssec.allow_all_policy,
            )
            self.assertEqual(ds, example_ds_sha1)

    def testMakeExampleSHA1DSValidationOkByPolicy(self):  # type: () -> None
        algorithm: Any
        for algorithm in ("SHA1", "sha1", dns.dnssec.DSDigest.SHA1):
            ds = dns.dnssec.make_ds(
                abs_example,
                example_sep_key,
                algorithm,
                policy=dns.dnssec.allow_all_policy,
            )
            self.assertEqual(ds, example_ds_sha1)
            ds = dns.dnssec.make_ds(
                "example.", example_sep_key, algorithm, validating=True
            )
            self.assertEqual(ds, example_ds_sha1)

    def testMakeExampleSHA1DSDeniedByPolicy(self):  # type: () -> None
        with self.assertRaises(dns.dnssec.DeniedByPolicy):
            ds = dns.dnssec.make_ds(abs_example, example_sep_key, "SHA1")
            self.assertEqual(ds, example_ds_sha1)

    def testMakeExampleSHA256DS(self):  # type: () -> None
        algorithm: Any
        for algorithm in ("SHA256", "sha256", dns.dnssec.DSDigest.SHA256):
            ds = dns.dnssec.make_ds(abs_example, example_sep_key, algorithm)
            self.assertEqual(ds, example_ds_sha256)

    def testMakeExampleSHA384DS(self):  # type: () -> None
        algorithm: Any
        for algorithm in ("SHA384", "sha384", dns.dnssec.DSDigest.SHA384):
            ds = dns.dnssec.make_ds(abs_example, example_sep_key, algorithm)
            self.assertEqual(ds, example_ds_sha384)

    def testMakeSHA256DS(self):  # type: () -> None
        ds = dns.dnssec.make_ds(abs_dnspython_org, sep_key, "SHA256")
        self.assertEqual(ds, good_ds)

    def testMakeSHA256CDS(self):  # type: () -> None
        cds = dns.dnssec.make_cds(abs_dnspython_org, sep_key, "SHA256")
        self.assertEqual(cds, good_cds)

    def testInvalidAlgorithm(self):  # type: () -> None
        algorithm: Any
        for algorithm in (10, "shax"):
            with self.assertRaises(dns.dnssec.UnsupportedAlgorithm):
                ds = dns.dnssec.make_ds(abs_example, example_sep_key, algorithm)

    def testReservedDigestType(self):  # type: () -> None
        with self.assertRaises(dns.exception.SyntaxError) as cm:
            dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                f"18673 3 0 71b71d4f3e11bbd71b4eff12cde69f7f9215bbe7",
            )
        self.assertEqual("digest type 0 is reserved", str(cm.exception))

    def testUnknownDigestType(self):  # type: () -> None
        digest_types = [dns.rdatatype.DS, dns.rdatatype.CDS]
        for rdtype in digest_types:
            rd = dns.rdata.from_text(
                dns.rdataclass.IN,
                rdtype,
                f"18673 3 5 71b71d4f3e11bbd71b4eff12cde69f7f9215bbe7",
            )
            assert isinstance(rd, dns.rdtypes.ANY.DS.DS) or isinstance(
                rd, dns.rdtypes.ANY.CDS.CDS
            )
            self.assertEqual(rd.digest_type, 5)
            self.assertEqual(
                rd.digest, bytes.fromhex("71b71d4f3e11bbd71b4eff12cde69f7f9215bbe7")
            )

    def testInvalidDigestLength(self):  # type: () -> None
        test_records = []
        for rdata in [example_ds_sha1, example_ds_sha256, example_ds_sha384]:
            flags, digest = rdata.to_text().rsplit(" ", 1)

            # Make sure the construction is working
            dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.DS, f"{flags} {digest}"
            )

            test_records.append(
                f"{flags} {digest[:len(digest)//2]}"
            )  # too short digest
            test_records.append(f"{flags} {digest*2}")  # too long digest

        for record in test_records:
            with self.assertRaises(dns.exception.SyntaxError) as cm:
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, record)

            self.assertEqual(
                "digest length inconsistent with digest type", str(cm.exception)
            )

    def testInvalidDigestLengthCDS0(self):  # type: () -> None
        # Make sure the construction is working
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CDS, f"0 0 0 00")

        test_records = {
            "expecting another identifier": ["0 0 0", "0 0 0 "],
            "digest length inconsistent with digest type": ["0 0 0 0000"],
            "Odd-length string": ["0 0 0 0", "0 0 0 000"],
        }
        for msg, records in test_records.items():
            for record in records:
                with self.assertRaises(dns.exception.SyntaxError) as cm:
                    dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.CDS, record)
                self.assertEqual(msg, str(cm.exception))

    def testMakeCDS(self):  # type: () -> None
        name = dns.name.from_text("example.com")
        key = ed448.Ed448PrivateKey.generate()

        for dnskey in [
            dns.dnssec.make_dnskey(
                key.public_key(), algorithm=dns.dnssec.Algorithm.ED448
            ),
            dns.dnssec.make_cdnskey(
                key.public_key(), algorithm=dns.dnssec.Algorithm.ED448
            ),
        ]:
            dnskey_rdataset = dns.rdataset.from_rdata_list(3600, [dnskey])
            cds_rdataset = dns.dnssec.dnskey_rdataset_to_cds_rdataset(
                name, dnskey_rdataset, "SHA256"
            )
            self.assertEqual(len(dnskey_rdataset), len(cds_rdataset))
            for d, c in zip(dnskey_rdataset, cds_rdataset):
                self.assertTrue(
                    isinstance(
                        d,
                        (
                            dns.rdtypes.ANY.DNSKEY.DNSKEY,
                            dns.rdtypes.ANY.CDNSKEY.CDNSKEY,
                        ),
                    )
                )
                self.assertTrue(isinstance(c, dns.rdtypes.ANY.CDS.CDS))
                self.assertEqual(dns.dnssec.key_id(d), c.key_tag)
                self.assertEqual(d.algorithm, c.algorithm)

    def testMakeManyDSfromCDS(self):  # type: () -> None
        name = dns.name.from_text("example.com")
        nkeys = 3
        algorithms = ["SHA256", "SHA384"]
        keys = [ed448.Ed448PrivateKey.generate() for _ in range(0, nkeys)]

        dnskeys = [
            dns.dnssec.make_dnskey(
                key.public_key(), algorithm=dns.dnssec.Algorithm.ED448
            )
            for key in keys
        ]

        dnskey_rdataset = dns.rdataset.from_rdata_list(3600, dnskeys)

        cds_rdataset = dns.dnssec.dnskey_rdataset_to_cds_rdataset(
            name, dnskey_rdataset, "SHA256"
        )
        cds_rrset = dns.rrset.from_rdata_list(name, 3600, cds_rdataset)

        ds_rdataset = dns.dnssec.make_ds_rdataset(cds_rrset, algorithms)

        self.assertEqual(len(cds_rdataset), nkeys)

    def testMakeManyDSfromDNSKEY(self):  # type: () -> None
        name = dns.name.from_text("example.com")
        nkeys = 3
        algorithms = ["SHA256", "SHA384"]
        keys = [ed448.Ed448PrivateKey.generate() for _ in range(0, nkeys)]

        dnskeys = [
            dns.dnssec.make_dnskey(
                key.public_key(), algorithm=dns.dnssec.Algorithm.ED448
            )
            for key in keys
        ]

        dnskey_rrset = dns.rrset.from_rdata_list(name, 3600, dnskeys)

        ds_rdataset = dns.dnssec.make_ds_rdataset(dnskey_rrset, algorithms)

        self.assertEqual(len(ds_rdataset), nkeys * len(algorithms))


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class DNSSECMakeDNSKEYTestCase(unittest.TestCase):
    def testKnownDNSKEYs(self):  # type: () -> None
        for tk in test_dnskeys:
            print(tk.command)
            key = load_pem_private_key(tk.private_pem.encode(), password=None)
            rdata1 = str(dns.dnssec.make_dnskey(key.public_key(), tk.algorithm))
            rdata2 = str(
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, tk.dnskey)
            )
            self.assertEqual(rdata1, rdata2)

    def testInvalidMakeDNSKEY(self):  # type: () -> None
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=1024,
            backend=default_backend(),
        )
        with self.assertRaises(dns.dnssec.AlgorithmKeyMismatch):
            dns.dnssec.make_dnskey(key.public_key(), dns.dnssec.Algorithm.ED448)

        with self.assertRaises(TypeError):
            dns.dnssec.make_dnskey("xyzzy", dns.dnssec.Algorithm.ED448)

        key = dsa.generate_private_key(2048)
        with self.assertRaises(ValueError):
            dns.dnssec.make_dnskey(key.public_key(), dns.dnssec.Algorithm.DSA)

    def testMakeCDNSKEY(self):  # type: () -> None
        key = ed448.Ed448PrivateKey.generate()
        dnskey = dns.dnssec.make_dnskey(
            key.public_key(), algorithm=dns.dnssec.Algorithm.ED448
        )
        cdnskey = dns.dnssec.make_cdnskey(
            key.public_key(), algorithm=dns.dnssec.Algorithm.ED448
        )

        self.assertEqual(dnskey.flags, cdnskey.flags)
        self.assertEqual(dnskey.protocol, cdnskey.protocol)
        self.assertEqual(dnskey.algorithm, cdnskey.algorithm)
        self.assertEqual(dnskey.key, cdnskey.key)

        dnskey_rdataset = dns.rdataset.from_rdata_list(3600, [dnskey])
        cdnskey_rdataset = dns.dnssec.dnskey_rdataset_to_cdnskey_rdataset(
            dnskey_rdataset
        )
        self.assertEqual(len(dnskey_rdataset), len(cdnskey_rdataset))
        for d, c in zip(dnskey_rdataset, cdnskey_rdataset):
            self.assertTrue(isinstance(d, dns.rdtypes.ANY.DNSKEY.DNSKEY))
            self.assertTrue(isinstance(c, dns.rdtypes.ANY.CDNSKEY.CDNSKEY))
            self.assertEqual(d, c)

    # XXXRTH This test is fine but is noticably slow, so I have commented it out for
    # now

    # def testRSALargeExponent(self):  # type: () -> None
    #     for key_size, public_exponent, dnskey_key_length in [
    #         (1024, 3, 130),
    #         (1024, 65537, 132),
    #         (2048, 3, 258),
    #         (2048, 65537, 260),
    #         (4096, 3, 514),
    #         (4096, 65537, 516),
    #     ]:
    #         key = rsa.generate_private_key(
    #             public_exponent=public_exponent,
    #             key_size=key_size,
    #             backend=default_backend(),
    #         )
    #         dnskey = dns.dnssec.make_dnskey(
    #             key.public_key(), algorithm=dns.dnssec.Algorithm.RSASHA256
    #         )
    #         self.assertEqual(len(dnskey.key), dnskey_key_length)


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class DNSSECSignatureTestCase(unittest.TestCase):
    def testSignatureData(self):  # type: () -> None
        rrsig_template = abs_soa_rrsig[0]
        data = dns.dnssec._make_rrsig_signature_data(abs_soa, rrsig_template)

    def testSignatureRSASHA1(self):  # type: () -> None
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self._test_signature(key, dns.dnssec.Algorithm.RSASHA1, abs_soa)

    def testSignatureRSASHA256(self):  # type: () -> None
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self._test_signature(key, dns.dnssec.Algorithm.RSASHA256, abs_soa)

    def testSignatureECDSAP256SHA256(self):  # type: () -> None
        key = ec.generate_private_key(curve=ec.SECP256R1, backend=default_backend())
        self._test_signature(key, dns.dnssec.Algorithm.ECDSAP256SHA256, abs_soa)

    def testSignatureECDSAP384SHA384(self):  # type: () -> None
        key = ec.generate_private_key(curve=ec.SECP384R1, backend=default_backend())
        self._test_signature(key, dns.dnssec.Algorithm.ECDSAP384SHA384, abs_soa)

    def testSignatureED25519(self):  # type: () -> None
        key = ed25519.Ed25519PrivateKey.generate()
        self._test_signature(key, dns.dnssec.Algorithm.ED25519, abs_soa)

    def testSignatureED448(self):  # type: () -> None
        key = ed448.Ed448PrivateKey.generate()
        self._test_signature(key, dns.dnssec.Algorithm.ED448, abs_soa)

    def testSignRdataset(self):  # type: () -> None
        key = ed448.Ed448PrivateKey.generate()
        name = dns.name.from_text("example.com")
        rdataset = dns.rdataset.from_text_list("in", "a", 30, ["10.0.0.1", "10.0.0.2"])
        rrset = (name, rdataset)
        self._test_signature(key, dns.dnssec.Algorithm.ED448, rrset)

    def testSignWildRdataset(self):  # type: () -> None
        key = ed448.Ed448PrivateKey.generate()
        name = dns.name.from_text("*.example.com")
        rdataset = dns.rdataset.from_text_list("in", "a", 30, ["10.0.0.1", "10.0.0.2"])
        rrset = (name, rdataset)
        rrsigset = self._test_signature(key, dns.dnssec.Algorithm.ED448, rrset)
        self.assertEqual(rrsigset[0].labels, 2)

    def _test_signature(self, key, algorithm, rrset, signer=None, policy=None):
        ttl = 60
        lifetime = 3600
        if isinstance(rrset, tuple):
            rrname = rrset[0]
        else:
            rrname = rrset.name
        signer = signer or rrname
        dnskey = dns.dnssec.make_dnskey(
            public_key=key.public_key(), algorithm=algorithm
        )
        dnskey_rrset = dns.rrset.from_rdata(signer, ttl, dnskey)
        rrsig = dns.dnssec.sign(
            rrset=rrset,
            private_key=key,
            dnskey=dnskey,
            lifetime=lifetime,
            signer=signer,
            verify=True,
            policy=policy,
        )
        keys = {signer: dnskey_rrset}
        rrsigset = dns.rrset.from_rdata(rrname, ttl, rrsig)
        dns.dnssec.validate(rrset=rrset, rrsigset=rrsigset, keys=keys, policy=policy)
        return rrsigset


if __name__ == "__main__":
    unittest.main()
