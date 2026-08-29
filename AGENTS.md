# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## What this project is

`dnspython` is a DNS toolkit for Python (import name `dns`). It provides both
high-level query/resolver APIs and low-level classes for directly manipulating
DNS messages, names, rdata, zones, and transactions. The default installation
has no dependencies outside the standard library; optional features
(DNSSEC, DoH, DoQ, IDNA, Trio, WMI) are gated behind extras and runtime
feature checks (see Architecture below).

## Commands

This project uses `uv` for environment/dependency management and its
build backend (`uv_build`).

- Run the full test suite: `pytest` (or `make test`)
- Run a single test file: `pytest tests/test_name.py`
- Run a single test case: `pytest tests/test_name.py -k test_bad_escape` or
  `pytest tests/test_name.py::NameTestCase::test_bad_escape` (tests are
  `unittest.TestCase` classes, executed through pytest)
- Type check: `pyright dns` and `ty check dns` (or `make pyright`, `make ty`, `make type`)
- Lint: `ruff check dns` (or `make ruff`) — note lint only covers `dns/`, not `tests/`
- Format: `black dns examples tests` (or `make black`)
- Coverage: `make cov` (writes `htmlcov/`, restricted to `dns/*`)
- Build docs: `make doc` (Sphinx, output in `doc/_build`)
- Build a wheel/sdist: `make build`
- Clean build/test artifacts: `make clean`

CI (`.github/workflows/ci.yml`) runs `pyright dns`, `ruff check dns`, and
`pytest` across Python 3.10–3.15-dev and PyPy on Linux and Windows. Match
that: keep new code typed and passing both `pyright` and `ty`, and keep
`ruff` clean.

## Architecture

### Core data model

DNS data flows through a consistent layered model, and most non-trivial
features touch several of these layers at once:

- `dns.name.Name` — immutable, absolute-or-relative domain names.
- `dns.rdataclass` / `dns.rdatatype` — enum-like registries for RR classes
  (IN, CH, ...) and RR types (A, MX, DNSKEY, ...), extensible at runtime via
  `register_class`/`register_type` for private-use types.
- `dns.rdata.Rdata` — base class for a single rdata record. Concrete types
  live under `dns/rdtypes/{CLASS}/{TYPE}.py` (e.g. `dns/rdtypes/IN/A.py`) or
  `dns/rdtypes/ANY/{TYPE}.py` for class-independent types, plus shared mixins
  in `dns/rdtypes/*base.py` (e.g. `dnskeybase.py`, `svcbbase.py`,
  `txtbase.py`). `dns.rdata.get_rdata_class()` dynamically imports the right
  module by convention (`dns.rdtypes.{CLASSTEXT}.{TYPETEXT}`, falling back to
  `ANY`, then a generic implementation) — adding a new RR type means adding a
  module in the conventional location, not registering it elsewhere.
- `dns.rdataset.Rdataset` — an rdata class/type/covers plus a set of `Rdata`.
- `dns.rrset.RRset` — an `Rdataset` bound to an owner `dns.name.Name`.
- `dns.message.Message` — a full DNS message (question/answer/authority/
  additional sections, EDNS, TSIG); `dns.message.make_query`,
  `from_text`/`from_wire` and `to_text`/`to_wire` are the main entry points.

Every layer generally supports both `from_text`/`to_text` (master-file/
presentation format, via `dns.tokenizer`) and `from_wire`/`to_wire`
(binary format, via `dns.wire`/`dns.renderer`), and these must round-trip.
Text/wire style formatting is controlled by `dns.name.NameStyle` /
`dns.rdata.RdataStyle` and rendered via `to_styled_text()`.

### Immutability

`dns.immutable` provides an `@dns.immutable.immutable` class decorator used
throughout (`Name`, `Rdata`, frozen `Rdataset`/`RRset` variants, etc.) to make
core objects hashable and safe to share/cache. `dns.set.Set` is the generic
mutable-set base that `Rdataset`, `dns.namedict.NameDict`, and zone node
classes build on.

### Query execution: sync, async, and backends

- `dns.query` — synchronous UDP/TCP/TLS/HTTPS (DoH) queries.
- `dns.asyncquery` — the async equivalents, dispatched through a pluggable
  backend abstraction (`dns.asyncbackend`, `dns._asyncio_backend`,
  `dns._trio_backend`) so the same code paths support both `asyncio` and
  `trio`.
- `dns.resolver` / `dns.asyncresolver` — stub resolver on top of
  `dns.query`/`dns.asyncquery`, with OS-specific system configuration readers
  (`dns/win32util.py` for Windows, `/etc/resolv.conf` parsing elsewhere) and a
  `dns.nameserver.Nameserver` abstraction for per-nameserver transport
  (Do53/DoT/DoH/DoQ) used by `dns.resolver.Resolver.resolve`.
- `dns.quic` — DNS-over-QUIC implementation with the same sync/asyncio/trio
  split (`_sync.py`, `_asyncio.py`, `_trio.py`) behind `_common.py`.
- `dns._features.have()` gates optional-dependency code paths (cryptography,
  httpx2/h2, aioquic, idna, trio, wmi) by checking installed package versions
  at runtime rather than hard-importing them; new optional integrations
  should follow this pattern instead of adding hard dependencies.

### Zones, transactions, and updates

- `dns.zone.Zone` holds a set of names each mapped to a node of rdatasets,
  and supports reading/writing master files (`dns.zonefile`) and comparing
  zones (`dns.zonediff`, exposed via `zone.py`'s diff helpers).
- `dns.transaction.Transaction`/`TransactionManager` is the unit-of-work
  abstraction for reading or atomically mutating a zone; `dns.versioned` adds
  a versioned zone implementation with historical version retention on top of
  it. Both zone-file loading and inbound zone transfers (`dns.xfr`) go
  through a transaction, and a "transaction setup" callable
  (e.g. `dns.transaction.TransactionLimiter`) can be supplied to constrain
  what a transaction is allowed to do.
- `dns.update.Update` builds RFC 2136 dynamic update messages.
- `dns.xfr` implements inbound AXFR/IXFR handling used by resolver/query
  helpers and by `dns.zone` for zone transfers.

### DNSSEC

- `dns.dnssec` provides validation/signing logic (RRSIG verification, DS
  digest computation, NSEC/NSEC3 handling) over the algorithm plumbing in
  `dns.dnssecalgs` (per-algorithm modules: `rsa.py`, `dsa.py`, `ecdsa.py`,
  `eddsa.py`, `mldsa.py`, dispatched through `base.py`/`cryptography.py`),
  gated by the `dnssec` extra (`cryptography` package) via `dns._features`.

### Cross-cutting conventions

- Modules prefixed with `_` (`_features.py`, `_asyncbackend.py`,
  `_immutable_ctx.py`, `_render_util.py`, `_tls_util.py`, `_file_util.py`,
  `_ddr.py`, `_no_ssl.py`) are internal implementation details, not part of
  the public API.
- Public modules generally define a `dns.exception.DNSException` subclass (or
  several) for their own error conditions rather than raising built-in
  exceptions directly; follow that convention for new error paths.
- Tests live in `tests/` as pytest or `unittest.TestCase`-based modules named
  `test_*.py`, run through pytest; test fixtures/data files (`.good`, `.text`,
  `.generic`, `.pickle`, sample zone files, TLS certs under `tests/tls/`,
  TSIG keys under `tests/tsigkeys/`) sit alongside the test code and are also
  referenced in `pyproject.toml`'s `source-include` for packaging.  New tests
  that are not augmenting existing test suites may use pytest instead of unittest.
- Some of the tests in the test suite are "live" and test against the Internet.
  If Internet connectivity is not available, the NO_INTERNET environment variable
  can be defined before running the tests, and the test suite will skip the live
  tests.
- Dnspython has high test coverage; 94% for the whole project, and many important
  modules have 100% coverage or close to it.  Code changes should preserve or improve
  the coverage whenever reasonable.  Coverage should cover all branch paths when
  reasonable.  Uninteresting failures that are hard to cover may be ignored with
  `pragma: no cover`.
- Backwards compatibility is important!  Incompatible changes should generally be
  avoided, but when they need to occur, they should be as small as possible and
  documented.
- The project supports all CPython 3 releases that have not reached end-of-life, as
  well as Pypy 3.11.  Once a Python release has reached end-of-life, code may be
  refactored to use features of the new least release.

## Documentation

Documentation is important.  All public types, attributes, and APIs should be
documented in the source.   Additionally, there is a manual of RST source in
`doc/` which includes not only auto-generated documentation extracted from the source,
but additional "big picture" documentation and other helpful references.  When updating
code, consider if anything in `doc/` needs to be updated as well.

The documentation file `doc/rfc.rst` is a good starting place for any DNS questions.
When adding or updating code, and you know it is associated with an RFC, add a link
for the RFC to `doc/rfc.rst`.
