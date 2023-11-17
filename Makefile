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

build:
	hatch build

clean:
	rm -rf htmlcov .coverage
	rm -rf .pytest_cache
	rm -rf .ruff_cache
	rm -rf .mypy_cache
	rm -rf doc/_build
	rm -rf dist
	rm -rf build

doc:
	cd doc; make html

test:
	hatch run pytest

check: test

type:
	hatch run python -m mypy --install-types --non-interactive --disallow-incomplete-defs dns

lint:
	hatch run pylint dns

flake:
	hatch run flake8 dns

ruff:
	hatch run ruff dns

cov:
	hatch run coverage run --branch -m pytest
	hatch run coverage html --include 'dns/*'
	hatch run coverage report --include 'dns/*'

black:
	hatch run black dns examples tests
