from dataclasses import dataclass

from dns.dnssectypes import Algorithm


@dataclass(frozen=True)
class TestKey:
    command: str
    private_pem: str
    dnskey: str
    algorithm: int


test_dnskeys = [
    TestKey(
        command="openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048",
        private_pem="""
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDHve8aGCaof3lX
Cc6QREh9gFvtc0pIm8iZAayiRu1KNS6EH2mN27+9jbfKRETywsxGN86XH/LZEEXH
C0El2YMJGwRbg7OqjUp14zEI33X/34jZZsqlHWbzJ2WBLY49K9mBengDLdQu5Ve9
8YWl+QYDoyRrTxqfEDgL7JZ0gECQuFjV//cIiovIaoKcffCGmWDY0QknPtHzn8X4
LQVx/S21uGNPZM8JcSw6fgbJ/hv+cct4x3JtrSktf2XDBH8HZZ/fbxHqSSBuQ/Y+
Jvx6twptxbY0LFALDZhidd1HZxsIf8uPkf4kfswSGEYeZQDDtQamG1q4IbRb/PZM
PHtCXydrAgMBAAECggEBAK9f/r3EkrzDIADh5XIZ4iP/Pbeg0Ior7dcZ9z+MUvAi
/bKX+g/J7/I4qjR3+KnFi6HjggqCzLD1bq6zHQJkln66L/tCCdAnukcDsZv+yBZf
aEKp1CdhR3EbGC5xlz/ybkkXBKSV6oU6bO2jUBtIKJWs+l8V12Pt06f0lK25pfbp
uCDbBDA7uIMJIFaQ1jqejaFpCROTuFyJVS5QbyMJlWBhx+TvvQbpgFltqPHji+/R
0V1CY4TI89VB/phPQJdf0bwUbvd7pOp8WL/W0NB+TzOWhOsqlmy13D30D7/IrbOu
OlDOPcfOs+g+dSiloO5hnSw1+mAd8vlkFvohEZz0vhECgYEA6QxXxHwCwSZ1n4i/
h5O0QfQbZSi8piDknzgyVvZp9cH9/WFhBOErvfbm4m2XLSaCsTrtlPEeEfefv73v
nMyY8dE/yPr64NZrMjLv/NfM6+fH5oyGmXcARrQD/KG703IRlq1NbzoClFcsMhuc
qbgY8I1CbvlQ8iaxiKvFGD3aFz8CgYEA22nd2MpxK33DAirmUDKJr24iQ2xQM33x
39gzbPPRQKU55OqpdXk9QcMB7q6mz7i9Phqia1JqqP3qc38be14mG3R0sT6glBPg
i8FUO+eTAHL6XYzd8w0daTnYmHo1xuV8+h4srsdoYrqwcESLBt3mJ2wE8eAlNk9s
Qnil9ZLyMNUCgYEA3Fp2Vmtnc1g5GXqElt37L+1vRcwp6+7oHQBW4NEnyV7/GGjO
An4iDQF6uBglPGTQaGGuqQj/hL+dxgACo0D1UJio9hERzCwRuapeLrWhpmFHK2Au
GMdjdHbb2jDW1wxhQxZkREoWjEqMmGhxTiyrMDBw41tLxVr+vJqlxtEc+KMCgYEA
n3tv+WgMomQjHqw4BAr38T/IP+G22fatnNr1ZjhC3Q476px22CBr2iT4fpkMPug1
BbMuY3vgcz088P5u51kjsckQGNVAuuFH0c2QgIpuW2E3glAl88iQnC+jtBEAjbW5
BcRxDgl7Ymf4X2Iy+6bG59ioL3eRFMzeD+LKHpnU2JECgYA7kJn1MJHeB7LYkLpS
lJ9PrYW3gfGRMoeEifhTs0f4FJDqbuiT8tsrEWUOJhsBebpXR9bfMD+F8aJ6Re3d
sZio5F16RuyuhwHv7agNfIcrCCXIs2xERN+q8D0Gi6LzwrtGxeaRPQnQFXo7kEOQ
HzK7xZItz01yelD1En+o4m2/Dg==
-----END PRIVATE KEY-----
""",
        dnskey="256 3 8 AwEAAce97xoYJqh/eVcJzpBESH2AW+1zSkibyJkBrKJG7Uo1LoQfaY3bv72Nt8pERPLCzEY3zpcf8tkQRccLQSXZgwkbBFuDs6qNSnXjMQjfdf/fiNlmyqUdZvMnZYEtjj0r2YF6eAMt1C7lV73xhaX5BgOjJGtPGp8QOAvslnSAQJC4WNX/9wiKi8hqgpx98IaZYNjRCSc+0fOfxfgtBXH9LbW4Y09kzwlxLDp+Bsn+G/5xy3jHcm2tKS1/ZcMEfwdln99vEepJIG5D9j4m/Hq3Cm3FtjQsUAsNmGJ13UdnGwh/y4+R/iR+zBIYRh5lAMO1BqYbWrghtFv89kw8e0JfJ2s=",
        algorithm=Algorithm.RSASHA256,
    ),
    TestKey(
        command="openssl genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:4096",
        private_pem="""
-----BEGIN PRIVATE KEY-----
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
bVQXjmugND3w6dydVZp/DrvEqfE1Ib0=
-----END PRIVATE KEY-----
""",
        dnskey="256 3 8 AwEAAcj+jhGMD2D+pZINqBY5g/61jl/cRXk/yQo/c4zH5FEL+zgmfNBcqDL/JYzd4Kc9ydjLVqa2vgsKlCvBl37wNXlO6n9Zms8dC7lihGAtv6gqe/DY0YwxsZDqOV6EDxN9+4XVtFB/VM8sFFospEnv1J6a+LIdxm6eq2OK/yZsOYWQyZQAVVAWcIat2/S+TyZuTGn3xQSTPAEqTgR3bCJBkCXUVYylZSG0B5m4kLhzW0dTXE2M3hzZeZiiRG8rSPf3qXoHSKH+CL3A5h/qN5OXmrSVK1v43Q9p5C+WPI4KOjvleoyRzdxVJpn/16SSmtIVnJXlR9LVqOPmsSSHg4f/0jIhMzx4WisyVnlGqGemfvG8uHXahnUBmSSLbHdWriHw7je5Uga0pdIaTaSse6xuN69WxrnOLNsdN3ygFpSu9SE5jUvw5KbQyI+tJAZFpXJDUDIF3eoSTACqC5m85RhYTfQMrxOiISaOORvV0hawlrgN4SS6H0iiHYceMthqfc+ilmqRGtjhkB0vcgscL+oiHjw2/fcS39DkkTlo9ZKWo9k3Rn82COAAfGyxZW/9L1yYCs0cTGesaKMQzE/xTaZcvxUplM2w0jXPEg61GO65W8bKLUU68Pye0zh5Dn2KES/+zKv4b14llnAs6cVCqoKRegHONbCUWsAP+RcgmzQxC8uT",
        algorithm=Algorithm.RSASHA256,
    ),
    TestKey(
        command="openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve",
        private_pem="""
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJFyT16nmjmDgEF2v
1iTperYVGR52zVT8ej6A9eTmmSChRANCAASfsKTiVq2KNEKSUoYtPAXiZbDG6EEP
8TwdLumK8ge2F9AtE0Q343bnnZBCFpCxuvxtuWmS8QQwAWh8PizqKrDu
-----END PRIVATE KEY-----
""",
        dnskey="256 3 13 n7Ck4latijRCklKGLTwF4mWwxuhBD/E8HS7pivIHthfQLRNEN+N2552QQhaQsbr8bblpkvEEMAFofD4s6iqw7g==",
        algorithm=Algorithm.ECDSAP256SHA256,
    ),
    TestKey(
        command="openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve",
        private_pem="""
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCNSZ3SrRmdh8wcUVPO
h9ea2zw9Jyc3P1XuP2nOYZR/aQMHfScCtWA3AsMCcsseEmihZANiAATv2H3Q3jrI
aH/Vmit9RefIpnh+iZzpyk29/m1EJKgkkwbA0OHClk8Nt7RL/4CO4CUpzaOcqamN
6B48G68LN4yZByMKt3z751qB86Z7rYc7SuOR0m7bPlXyUsO48+8o/hU=
-----END PRIVATE KEY-----
""",
        dnskey="256 3 14 79h90N46yGh/1ZorfUXnyKZ4fomc6cpNvf5tRCSoJJMGwNDhwpZPDbe0S/+AjuAlKc2jnKmpjegePBuvCzeMmQcjCrd8++dagfOme62HO0rjkdJu2z5V8lLDuPPvKP4V",
        algorithm=Algorithm.ECDSAP384SHA384,
    ),
    TestKey(
        command="openssl genpkey -algorithm ED25519",
        private_pem="""
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKGelcdVWlxU5YlLE5/LAEfqhZq7P9s0NHlQqxOjBvcS
-----END PRIVATE KEY-----""",
        dnskey="256 3 15 iHaBu3tWzJxuuMSzk1WMwCGF3LD60n0fkOdaCCqsL0A=",
        algorithm=Algorithm.ED25519,
    ),
    TestKey(
        command="openssl genpkey -algorithm ED448",
        private_pem="""
-----BEGIN PRIVATE KEY-----
MEcCAQAwBQYDK2VxBDsEOfGENbZhfMbspoQV1c3/vljWPMFsIzef7M111gU0QTva
dUd0khisgJ/gk+I1DWLtf/6M4wxXje5FLg==
-----END PRIVATE KEY-----
""",
        dnskey="256 3 16 ziFYQq6fEXyNKPGzq2GErJxCl9979MKNdW46r4Bqn/waS+iIAmAbaTG3klpwqJtl+Qvdj2xGqJwA",
        algorithm=Algorithm.ED448,
    ),
]
