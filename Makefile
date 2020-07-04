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

# $Id: Makefile,v 1.16 2004/03/19 00:17:27 halley Exp $

PYTHON=python

all:
	${PYTHON} ./setup.py build

install:
	${PYTHON} ./setup.py install

clean:
	${PYTHON} ./setup.py clean --all
	find . -name '*.pyc' -exec rm {} \;
	find . -name '*.pyo' -exec rm {} \;
	rm -f TAGS
	rm -rf htmlcov .coverage
	rm -rf .pytest_cache

distclean: clean docclean
	rm -rf build dist
	rm -f MANIFEST
	rm -rf dnspython.egg-info

doc:
	cd doc; make html

docclean:
	rm -rf doc/_build

check: test

test:
	cd tests; make test

potest:
	poetry run pytest

potestlf:
	poetry run pytest --lf

potype:
	poetry run python -m mypy examples tests dns/*.py

poflake:
	poetry run flake8 dns

pocov:
	poetry run coverage run -m pytest
	poetry run coverage html --include 'dns*'
	poetry run coverage report --include 'dns*'

pokit:
	po run python setup.py sdist --formats=zip bdist_wheel

