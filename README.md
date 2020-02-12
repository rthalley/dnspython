# dnspython

[![Build Status](https://travis-ci.org/rthalley/dnspython.svg?branch=master)](https://travis-ci.org/rthalley/dnspython)
[![PyPI version](https://badge.fury.io/py/dnspython.svg)](https://badge.fury.io/py/dnspython)
[![PyPI Statistics](https://img.shields.io/pypi/dm/dnspython.svg)](https://pypistats.org/packages/dnspython)


## INTRODUCTION

dnspython is a DNS toolkit for Python. It supports almost all record types. It
can be used for queries, zone transfers, and dynamic updates. It supports TSIG
authenticated messages and EDNS0.

dnspython provides both high and low level access to DNS. The high level classes
perform queries for data of a given name, type, and class, and return an answer
set. The low level classes allow direct manipulation of DNS zones, messages,
names, and records.

To see a few of the ways dnspython can be used, look in the `examples/` directory.

dnspython is a utility to work with DNS, `/etc/hosts` is thus not used. For
simple forward DNS lookups, it's better to use `socket.gethostbyname()`.

dnspython originated at Nominum where it was developed
to facilitate the testing of DNS software.

## INSTALLATION

* Many distributions have dnspython packaged for you, so you should
  check there first.
* If you have pip installed, you can do `pip install dnspython`
* If not just download the source file and unzip it, then run
  `sudo python setup.py install`

## ABOUT THIS RELEASE

This is the development version of dnspython 2.0.0

### Notices

Python 2.x support ended with the release of 1.16.0.  dnspython 2.0.0 and
later only support Python 3.4 and later.

The ChangeLog has been discontinued.  Please see the git history for detailed
change information.
