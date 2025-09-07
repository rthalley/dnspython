# Security Policy

## Supported Versions

The following versions would get a security update release if necessary.

| Version  | Supported          |
| -------- | ------------------ |
| 2.8.x    | :white_check_mark: |
| < 1.16.0 | :x:                |

For older version 2 releases, the normal security upgrade path is
to upgrade to the latest version 2 release.  Selective backports to
older 2.x versions may be considered on a case-by-case basis
if no API change is required.

## Reporting a Vulnerability

Send email to security@dnspython.org.  For confidentiality, use the following public key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBF7mj/kBEAC6UB++f8N8qCBQuRLzIHoZd5oEYpylm+C9CrbfA0BYQpql9L6s
Ty8C/aph3ZHqtKutsbotQjmnd2b5D/W1Ku5F1Z+B5/gr2ija9NV1u66wJjKOdHon
LLYMaquzIcQvwxkrjAcGd1BZsem0maHKR/iT2bpGOmLB0U89lnEmwmNgSh+vg+68
SzXl6WFAJd89J7+UIFUZm/qoyHp7sGzO3+q44ecupUeH+xDpuQVAxnMF7nWT8G+P
UZ6rT1AFz7f9PJ9Ul+szpALem9/YWZO7UpBqIfHzbOBEgcGB6RKm0Yk/RUSSYdk8
kFFvRogZwSPbIC5cYYbMRX8BGmaPGVVLAPnzvA7U0/3XRIOc0TCcjfW3n7mxZ1R+
YxcQfF63zys72dey77zoZCtLaWKifcNKJQcRIVUHoDRP1YAlDh45wm2W4QKKmdUn
eo8Ghl7IOhYeQi37OxtrA2cYEp0Y1oUaxYFo5NdLaW40asm9lAf1ZS9hrgK0ZHtK
F9aN9VFSmsbuvzDN+miQwNfoH1/hCDJtoZPXZ0Hqjy/hbC2WCE8Tdw2zBb4gZzfO
3nOcWSOOwrJqz0/Hl/7VE6eQDKq3rcc+BlhqW3WDxnK41RFJPkGyn+NauV+RDqlR
CoOj3JiAp6mH8HFdnd92OcKkf7ZDFU/jHvuk6WgZKN/fgNS+AwG+ErHGdQARAQAB
tCtEbnNweXRob24gU2VjdXJpdHkgPHNlY3VyaXR5QGRuc3B5dGhvbi5vcmc+iQJO
BBMBCAA4FiEErlGglzMd8tn0T8v2tEx7LtBQJQ8FAl7mj/kCGwMFCwkIBwIGFQoJ
CAsCBBYCAwECHgECF4AACgkQtEx7LtBQJQ+BOw//b413gZ4+/NkTH4L8qbtq4VmR
Y8m7qBG5uEqqZ4Nu0U+8m6uBvIVtSNkvmNgVvYRbjRIhSZr+bAqhPUa65m4/oN9s
/TliovKeZv0087o5wfe4eBs+4Yvt6kq5mazNKxHyIE3uvjmHNmVL3E7MPByJW0Yl
g7B1FEi90qCKc/8UAVyRZJeZr87wj4YV2R66EBwhylT9TKXU2Xxr7FXmjePeX9ZN
DsO2JxHQf7ZIGcFPeLsWDo7Vra+TPeoCr0Klq0Z4TvwXr24zTqin0MNp7xzXioW7
OpslEUJ5e8ce8g1Lyv5y9UUv7wQd6OClf+FXd9a/SQtjiflU+hFr8lG55YvOq3DO
JZn1peD8/QphdJ46DUuYf5fp8AFw4yNnMca6IiFgJ19Rd+zTFahgKdwA4q41ex9d
DEvjAs+JNuiKPbzckALYAPrklZfTk6OFWolg/XqSEFGdtxtw6787efe8xKlYBpvn
Q+zkxpRJfMfJwO7Z54KWgoy/YiwbGPeDtS8TX5OJLt04NBQ5WcK81qtIMstTZ7cp
SPuoDHS9UIhiedvG9yay/ob4Pe9lcBECv6+YpcWqu6vHS+qdzUflJQ+nZHIhfQXE
ymV4hRXOUbH9Rc8m3LViB+YYlBToLzSJar/W7DDORWAVfMqO5rmqZEYYG1CQvoiV
w4CapV4Jg9URwiqs+HG5Ag0EXuaP+QEQAOlGCchcxIy0jaQ6qTaG7eHF/CEMhk0u
wkZ7lfFsZvm/6wUItKfdfC0Y+HQx9fUVjzs1dtwvEhTKY1tfxF6Kyu/+oejCY+WU
ovjTq6PN+HxgDkMhd32HpznS06KByYEVW3XMtzgW9KKb37nDSs1OSv7kpdvp70tv
8uaNds95S1aReGVaio9lHikSJXUsjYH1pQhRbwr5bzR+LQVPsFhlKSF6PY31lRjU
UxN5koxogefehAgHRKktXYS89IUk1uM4yIoC13JJfsjUBXjpgZu1C/cFx8bEVNiW
42r7jugvuQAyBba7vgCE/BRP3V+ctE5asxLlLJWKfDlmiFFubFEc3oqmYOH4XEAt
ICA7lVC1bOAAhHaNy3K3Ae7PRNOwDb+cinpImmYQlky+clK3wSgfIrM10sDBag10
y5CyqziMN6h+n50zxNuxSX6//qRH4TL2AD4TmBugqC8gP0EPgMzot4H9c/SZcoTA
OC04ddlJtwTwDMx42C4vGjT0yXl3VfSqwfgA5lKusnM2jw82edzk3UdW8HSaSN3x
QWQ4cyEjbgnEL4AuY8RWTCHDNiovwN4jcDPfPyQp/3DbnxhDD9kJyuR6rcp8/WDA
vp666HQUmySz5vVUs1K1+hNeXA909aW/hT9hhXIkeAmp2wm3K95zIvc1foHKPR6O
EdqpaQFQA6LhABEBAAGJAjYEGAEIACAWIQSuUaCXMx3y2fRPy/a0THsu0FAlDwUC
XuaP+QIbDAAKCRC0THsu0FAlD1nBEACcyyZEwMK3RkD5BJVZTTXBjGRxUohvsx9G
tv/5YQFTHfjB/h5tvEI6fqmIUm+DoAzQNydzr/vpu5AA7WfUr59TmIVanvQHC2ir
vh08m37OdECORejbPzCj+BHUkAk3NblfKRXYyNduS0qBVB8eLRAAX6PwMeK3TFwy
z3lW9H5uLrj7wPc1d5932DeYWlYUF5mFyQzbgbhBW5wHN7B0iD6iNnBzMXoM6WRv
tWU9QGzCmbJaTVLh1W7yArr4qnibz/XaQ0+1XLl6dZIe3XFztlFaHJ58aQKBf7k9
IC70stP7A3xeb9hCttPJI4qPl6YJwiPp0OeMy5H+KPcfkk7gyTNlcjSBiC1vy6Nh
vpjLKJrTwEftfc8B+p0JwQGgOLWCqziodCbR5Tiw/6S2cSl94Cu8OTMxPgN7JXKA
0W0WjutHlAO1tlKITUl4qTYQ+7r7JaOU6IcnyQksUzpm47bqEYwoGmscWObpEhs3
e862BGb8qdY821UcReukRaKf4nW11mCul6VSvApaRVYxcK8EZklxpwJOtNKIKUzq
l9fXngLMi6Qas6xx/ti3eHtEom2atKMnuRlSM7idOZZGowLtf65GhxogVsuFJhCX
sp5LOiYu+1IxUgzHC1snMvG7JJ8JT9XkvlVdgSDrBtfseekBkkl6IQeL6J4nbywe
clqgUVNxjw==
=qmj5
-----END PGP PUBLIC KEY BLOCK-----
```
