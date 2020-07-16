# dnspython

[![Build Status](https://travis-ci.org/rthalley/dnspython.svg?branch=master)](https://travis-ci.org/rthalley/dnspython)
[![Documentation Status](https://readthedocs.org/projects/dnspython/badge/?version=latest)](https://dnspython.readthedocs.io/en/latest/?badge=latest)
[![PyPI version](https://badge.fury.io/py/dnspython.svg)](https://badge.fury.io/py/dnspython)
[![PyPI Statistics](https://img.shields.io/pypi/dm/dnspython.svg)](https://pypistats.org/packages/dnspython)
[![Build Status](https://dev.azure.com/halley0415/halley/_apis/build/status/rthalley.dnspython?branchName=master)](https://dev.azure.com/halley0415/halley/_build/latest?definitionId=1&branchName=master)
[![Coverage](https://codecov.io/github/rthalley/dnspython/coverage.svg?branch=master)](https://codecov.io/gh/rthalley/dnspython)
[![License: ISC](https://img.shields.io/badge/License-ISC-brightgreen.svg)](https://opensource.org/licenses/ISC)

## INTRODUCTION

dnspython is a DNS toolkit for Python. It supports almost all record types. It
can be used for queries, zone transfers, and dynamic updates. It supports TSIG
authenticated messages and EDNS0.

dnspython provides both high and low level access to DNS. The high level classes
perform queries for data of a given name, type, and class, and return an answer
set. The low level classes allow direct manipulation of DNS zones, messages,
names, and records.

To see a few of the ways dnspython can be used, look in the `examples/`
directory.

dnspython is a utility to work with DNS, `/etc/hosts` is thus not used. For
simple forward DNS lookups, it's better to use `socket.getaddrinfo()` or
`socket.gethostbyname()`.

dnspython originated at Nominum where it was developed
to facilitate the testing of DNS software.

## ABOUT THIS RELEASE

This is dnspython 2.0.0.
Please read
[What's New](https://dnspython.readthedocs.io/en/latest/whatsnew.html) for
information about the changes in this release.

## INSTALLATION

* Many distributions have dnspython packaged for you, so you should
  check there first.
* If you have pip installed, you can do `pip install dnspython`
* If not just download the source file and unzip it, then run
  `sudo python setup.py install`
* To install the latest from the master branch, run `pip install git+https://github.com/rthalley/dnspython.git`

If you want to use DNS-over-HTTPS, you must run
`pip install dnspython[doh]`.

If you want to use DNSSEC functionality, you must run
`pip install dnspython[dnssec]`.

If you want to use internationalized domain names (IDNA)
functionality, you must run
`pip install dnspython[idna]`

If you want to use the Trio asynchronous I/O package, you must run
`pip install dnspython[trio]`.

If you want to use the Curio asynchronous I/O package, you must run
`pip install dnspython[curio]`.

Note that you can install any combination of the above, e.g.:
`pip install dnspython[doh,dnssec,idna]`

### Notices

Python 2.x support ended with the release of 1.16.0.  dnspython 2.0.0 and
later only support Python 3.6 and later.

Documentation has moved to
[dnspython.readthedocs.io](https://dnspython.readthedocs.io).

The ChangeLog has been discontinued.  Please see the git history for detailed
change information.
