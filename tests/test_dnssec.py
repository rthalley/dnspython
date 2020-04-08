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

from __future__ import print_function

import unittest

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

# pylint: disable=line-too-long

abs_dnspython_org = dns.name.from_text('dnspython.org')

abs_keys = {
    abs_dnspython_org: dns.rrset.from_text(
        'dnspython.org.', 3600, 'IN', 'DNSKEY',
        '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=',
        '256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58 LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF'
    )
}

abs_keys_duplicate_keytag = {
    abs_dnspython_org: dns.rrset.from_text(
        'dnspython.org.', 3600, 'IN', 'DNSKEY',
        '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=',
        '256 3 5 AwEAAdSSg++++THIS/IS/NOT/THE/CORRECT/KEY++++++++++++++++ ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ ++++++++++++++++++++++++++++++++++++++++++++++++++++++++ AaOSydAF',
        '256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58 LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF'
    )
}

rel_keys = {
    dns.name.empty: dns.rrset.from_text(
        '@', 3600, 'IN', 'DNSKEY',
        '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=',
        '256 3 5 AwEAAdSSghOGjU33IQZgwZM2Hh771VGXX05olJK49FxpSyuEAjDBXY58 LGU9R2Zgeecnk/b9EAhFu/vCV9oECtiTCvwuVAkt9YEweqYDluQInmgP NGMJCKdSLlnX93DkjDw8rMYv5dqXCuSGPlKChfTJOLQxIAxGloS7lL+c 0CTZydAF'
    )
}

when = 1290250287

abs_soa = dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'SOA',
                              'howl.dnspython.org. hostmaster.dnspython.org. 2010020047 3600 1800 604800 3600')

abs_other_soa = dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'SOA',
                                    'foo.dnspython.org. hostmaster.dnspython.org. 2010020047 3600 1800 604800 3600')

abs_soa_rrsig = dns.rrset.from_text('dnspython.org.', 3600, 'IN', 'RRSIG',
                                    'SOA 5 2 3600 20101127004331 20101119213831 61695 dnspython.org. sDUlltRlFTQw5ITFxOXW3TgmrHeMeNpdqcZ4EXxM9FHhIlte6V9YCnDw t6dvM9jAXdIEi03l9H/RAd9xNNW6gvGMHsBGzpvvqFQxIBR2PoiZA1mX /SWHZFdbt4xjYTtXqpyYvrMK0Dt7bUYPadyhPFCJ1B+I8Zi7B5WJEOd0 8vs=')

rel_soa = dns.rrset.from_text('@', 3600, 'IN', 'SOA',
                              'howl hostmaster 2010020047 3600 1800 604800 3600')

rel_other_soa = dns.rrset.from_text('@', 3600, 'IN', 'SOA',
                                    'foo hostmaster 2010020047 3600 1800 604800 3600')

rel_soa_rrsig = dns.rrset.from_text('@', 3600, 'IN', 'RRSIG',
                                    'SOA 5 2 3600 20101127004331 20101119213831 61695 @ sDUlltRlFTQw5ITFxOXW3TgmrHeMeNpdqcZ4EXxM9FHhIlte6V9YCnDw t6dvM9jAXdIEi03l9H/RAd9xNNW6gvGMHsBGzpvvqFQxIBR2PoiZA1mX /SWHZFdbt4xjYTtXqpyYvrMK0Dt7bUYPadyhPFCJ1B+I8Zi7B5WJEOd0 8vs=')

sep_key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                              '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=')

good_ds = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                              '57349 5 2 53A79A3E7488AB44FFC56B2D1109F0699D1796DD977E72108B841F96 E47D7013')

when2 = 1290425644

abs_example = dns.name.from_text('example')

example_sep_key = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                                      '257 3 3 CI3nCqyJsiCJHTjrNsJOT4RaszetzcJPYuoH3F9ZTVt3KJXncCVR3bwn 1w0iavKljb9hDlAYSfHbFCp4ic/rvg4p1L8vh5s8ToMjqDNl40A0hUGQ Ybx5hsECyK+qHoajilUX1phYSAD8d9WAGO3fDWzUPBuzR7o85NiZCDxz yXuNVfni0uhj9n1KYhEO5yAbbruDGN89wIZcxMKuQsdUY2GYD93ssnBv a55W6XRABYWayKZ90WkRVODLVYLSn53Pj/wwxGH+XdhIAZJXimrZL4yl My7rtBsLMqq8Ihs4Tows7LqYwY7cp6y/50tw6pj8tFqMYcPUjKZV36l1 M/2t5BVg3i7IK61Aidt6aoC3TDJtzAxg3ZxfjZWJfhHjMJqzQIfbW5b9 q1mjFsW5EUv39RaNnX+3JWPRLyDqD4pIwDyqfutMsdk/Py3paHn82FGp CaOg+nicqZ9TiMZURN/XXy5JoXUNQ3RNvbHCUiPUe18KUkY6mTfnyHld 1l9YCWmzXQVClkx/hOYxjJ4j8Ife58+Obu5X')

example_ds_sha1 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                                      '18673 3 1 71b71d4f3e11bbd71b4eff12cde69f7f9215bbe7')

example_ds_sha256 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                                        '18673 3 2 eb8344cbbf07c9d3d3d6c81d10c76653e28d8611a65e639ef8f716e4e4e5d913')

example_ds_sha384 = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS,
                                        '18673 3 4 61ab241025c5f88d2537be04dcfba96f952adaefe0b382ecbc4108c97b75768c9e99fd16caed2a09634c51e8089fb84f')

when3 = 1379801800

abs_ecdsa256_keys = {
    abs_example: dns.rrset.from_text(
        'example.', 86400, 'IN', 'DNSKEY',
        "256 3 13 +3ss1sCpdARVA61DJigEsL/8quo2a8MszKtn2gkkfxgzFs8S2UHtpb4N fY+XFmNW+JK6MsCkI3jHYN8eEQUgMw==",
        "257 3 13 eJCEVH7AS3wnoaQpaNlAXH0W8wxymtT9P6P3qjN2ZCV641ED8pF7wZ5V yWfOpgTs6oaZevbJgehl/GaRPUgVyQ=="
    )
}

abs_ecdsa256_soa = dns.rrset.from_text('example.', 86400, 'IN', 'SOA',
                                       'ns1.example. hostmaster.example. 4 10800 3600 604800 86400')

abs_other_ecdsa256_soa = dns.rrset.from_text('example.', 86400, 'IN', 'SOA',
                                             'ns1.example. hostmaster.example. 2 10800 3600 604800 86401')

abs_ecdsa256_soa_rrsig = dns.rrset.from_text('example.', 86400, 'IN', 'RRSIG',
                                             "SOA 13 1 86400 20130921221753 20130921221638 7460 example. Sm09SOGz1ULB5D/duwdE2Zpn8bWbVBM77H6N1wPkc42LevvVO+kZEjpq 2nq4GOMJcih52667GIAbMrwmU5P2MQ==")

when4 = 1379804850

abs_ecdsa384_keys = {
    abs_example: dns.rrset.from_text(
        'example.', 86400, 'IN', 'DNSKEY',
        "256 3 14 1bG8qWviKNXQX3BIuG6/T5jrP1FISiLW/8qGF6BsM9DQtWYhhZUA3Owr OAEiyHAhQwjkN2kTvWiAYoPN80Ii+5ff9/atzY4F9W50P4l75Dj9PYrL HN/hLUgWMNVc9pvA",
        "257 3 14 mSub2n0KRt6u2FaD5XJ3oQu0R4XvB/9vUJcyW6+oo0y+KzfQeTdkf1ro ZMVKoyWXW9zUKBYGJpMUIdbAxzrYi7f5HyZ3yDpBFz1hw9+o3CX+gtgb +RyhHfJDwwFXBid9"
    )
}

abs_ecdsa384_soa = dns.rrset.from_text('example.', 86400, 'IN', 'SOA',
                                       'ns1.example. hostmaster.example. 2 10800 3600 604800 86400')

abs_other_ecdsa384_soa = dns.rrset.from_text('example.', 86400, 'IN', 'SOA',
                                             'ns1.example. hostmaster.example. 2 10800 3600 604800 86401')

abs_ecdsa384_soa_rrsig = dns.rrset.from_text('example.', 86400, 'IN', 'RRSIG',
                                             "SOA 14 1 86400 20130929021229 20130921230729 63571 example. CrnCu34EeeRz0fEhL9PLlwjpBKGYW8QjBjFQTwd+ViVLRAS8tNkcDwQE NhSV89NEjj7ze1a/JcCfcJ+/mZgnvH4NHLNg3Tf6KuLZsgs2I4kKQXEk 37oIHravPEOlGYNI")

abs_example_com = dns.name.from_text('example.com')

abs_ed25519_mx = dns.rrset.from_text('example.com.', 3600, 'IN', 'MX',
                                     '10 mail.example.com.')
abs_other_ed25519_mx = dns.rrset.from_text('example.com.', 3600, 'IN', 'MX',
                                           '11 mail.example.com.')
abs_ed25519_keys_1 = {
    abs_example_com: dns.rrset.from_text(
        'example.com', 3600, 'IN', 'DNSKEY',
        '257 3 15 l02Woi0iS8Aa25FQkUd9RMzZHJpBoRQwAQEX1SxZJA4=')
}
abs_ed25519_mx_rrsig_1 = dns.rrset.from_text('example.com.', 3600, 'IN', 'RRSIG',
                                             'MX 15 2 3600 1440021600 1438207200 3613 example.com. oL9krJun7xfBOIWcGHi7mag5/hdZrKWw15jPGrHpjQeRAvTdszaPD+QLs3fx8A4M3e23mRZ9VrbpMngwcrqNAg==')

abs_ed25519_keys_2 = {
    abs_example_com: dns.rrset.from_text(
        'example.com', 3600, 'IN', 'DNSKEY',
        '257 3 15 zPnZ/QwEe7S8C5SPz2OfS5RR40ATk2/rYnE9xHIEijs=')
}
abs_ed25519_mx_rrsig_2 = dns.rrset.from_text('example.com.', 3600, 'IN', 'RRSIG',
                                             'MX 15 2 3600 1440021600 1438207200 35217 example.com. zXQ0bkYgQTEFyfLyi9QoiY6D8ZdYo4wyUhVioYZXFdT410QPRITQSqJSnzQoSm5poJ7gD7AQR0O7KuI5k2pcBg==')

abs_ed448_mx = abs_ed25519_mx
abs_other_ed448_mx = abs_other_ed25519_mx

abs_ed448_keys_1 = {
    abs_example_com: dns.rrset.from_text(
        'example.com', 3600, 'IN', 'DNSKEY',
        '257 3 16 3kgROaDjrh0H2iuixWBrc8g2EpBBLCdGzHmn+G2MpTPhpj/OiBVHHSfPodx1FYYUcJKm1MDpJtIA')
}
abs_ed448_mx_rrsig_1 = dns.rrset.from_text('example.com.', 3600, 'IN', 'RRSIG',
                                           'MX 16 2 3600 1440021600 1438207200 9713 example.com. 3cPAHkmlnxcDHMyg7vFC34l0blBhuG1qpwLmjInI8w1CMB29FkEAIJUA0amxWndkmnBZ6SKiwZSAxGILn/NBtOXft0+Gj7FSvOKxE/07+4RQvE581N3Aj/JtIyaiYVdnYtyMWbSNyGEY2213WKsJlwEA')

abs_ed448_keys_2 = {
    abs_example_com: dns.rrset.from_text(
        'example.com', 3600, 'IN', 'DNSKEY',
        '257 3 16 kkreGWoccSDmUBGAe7+zsbG6ZAFQp+syPmYUurBRQc3tDjeMCJcVMRDmgcNLp5HlHAMy12VoISsA')
}
abs_ed448_mx_rrsig_2 = dns.rrset.from_text('example.com.', 3600, 'IN', 'RRSIG',
                                           'MX 16 2 3600 1440021600 1438207200 38353 example.com. E1/oLjSGIbmLny/4fcgM1z4oL6aqo+izT3urCyHyvEp4Sp8Syg1eI+lJ57CSnZqjJP41O/9l4m0AsQ4f7qI1gVnML8vWWiyW2KXhT9kuAICUSxv5OWbf81Rq7Yu60npabODB0QFPb/rkW3kUZmQ0YQUA')

when5 = 1440021600


@unittest.skipUnless(dns.dnssec._have_pyca,
                     "Python Cryptography cannot be imported")
class DNSSECValidatorTestCase(unittest.TestCase):

    def testAbsoluteRSAGood(self):  # type: () -> None
        dns.dnssec.validate(abs_soa, abs_soa_rrsig, abs_keys, None, when)

    def testDuplicateKeytag(self):  # type: () -> None
        dns.dnssec.validate(abs_soa, abs_soa_rrsig, abs_keys_duplicate_keytag, None, when)

    def testAbsoluteRSABad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(abs_other_soa, abs_soa_rrsig, abs_keys, None,
                                when)
        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testRelativeRSAGood(self):  # type: () -> None
        dns.dnssec.validate(rel_soa, rel_soa_rrsig, rel_keys,
                            abs_dnspython_org, when)

    def testRelativeRSABad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(rel_other_soa, rel_soa_rrsig, rel_keys,
                                abs_dnspython_org, when)
        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testAbsoluteECDSA256Good(self):  # type: () -> None
        dns.dnssec.validate(abs_ecdsa256_soa, abs_ecdsa256_soa_rrsig,
                            abs_ecdsa256_keys, None, when3)

    def testAbsoluteECDSA256Bad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(abs_other_ecdsa256_soa, abs_ecdsa256_soa_rrsig,
                                abs_ecdsa256_keys, None, when3)
        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testAbsoluteECDSA384Good(self):  # type: () -> None
        dns.dnssec.validate(abs_ecdsa384_soa, abs_ecdsa384_soa_rrsig,
                            abs_ecdsa384_keys, None, when4)

    def testAbsoluteECDSA384Bad(self):  # type: () -> None
        def bad():  # type: () -> None
            dns.dnssec.validate(abs_other_ecdsa384_soa, abs_ecdsa384_soa_rrsig,
                                abs_ecdsa384_keys, None, when4)
        self.assertRaises(dns.dnssec.ValidationFailure, bad)

    def testAbsoluteED25519Good(self):  # type: () -> None
        dns.dnssec.validate(abs_ed25519_mx, abs_ed25519_mx_rrsig_1,
                            abs_ed25519_keys_1, None, when5)
        dns.dnssec.validate(abs_ed25519_mx, abs_ed25519_mx_rrsig_2,
                            abs_ed25519_keys_2, None, when5)

    def testAbsoluteED25519Bad(self):  # type: () -> None
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(abs_other_ed25519_mx, abs_ed25519_mx_rrsig_1,
                                abs_ed25519_keys_1, None, when5)
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(abs_other_ed25519_mx, abs_ed25519_mx_rrsig_2,
                                abs_ed25519_keys_2, None, when5)

    def testAbsoluteED448Good(self):  # type: () -> None
        dns.dnssec.validate(abs_ed448_mx, abs_ed448_mx_rrsig_1,
                            abs_ed448_keys_1, None, when5)
        dns.dnssec.validate(abs_ed448_mx, abs_ed448_mx_rrsig_2,
                            abs_ed448_keys_2, None, when5)

    def testAbsoluteED448Bad(self):  # type: () -> None
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(abs_other_ed448_mx, abs_ed448_mx_rrsig_1,
                                abs_ed448_keys_1, None, when5)
        with self.assertRaises(dns.dnssec.ValidationFailure):
            dns.dnssec.validate(abs_other_ed448_mx, abs_ed448_mx_rrsig_2,
                                abs_ed448_keys_2, None, when5)

class DNSSECMakeDSTestCase(unittest.TestCase):

    def testMakeExampleSHA1DS(self):  # type: () -> None
        ds = dns.dnssec.make_ds(abs_example, example_sep_key, 'SHA1')
        self.assertEqual(ds, example_ds_sha1)

    def testMakeExampleSHA256DS(self):  # type: () -> None
        ds = dns.dnssec.make_ds(abs_example, example_sep_key, 'SHA256')
        self.assertEqual(ds, example_ds_sha256)

    def testMakeExampleSHA384DS(self):  # type: () -> None
        ds = dns.dnssec.make_ds(abs_example, example_sep_key, 'SHA384')
        self.assertEqual(ds, example_ds_sha384)

    def testMakeSHA256DS(self):  # type: () -> None
        ds = dns.dnssec.make_ds(abs_dnspython_org, sep_key, 'SHA256')
        self.assertEqual(ds, good_ds)


if __name__ == '__main__':
    unittest.main()
