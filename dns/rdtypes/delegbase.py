# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import base64
import enum
import struct
from typing import Any, Dict

import dns.enum
import dns.exception
import dns.immutable
import dns.ipv4
import dns.ipv6
import dns.name
import dns.rdata
import dns.renderer
import dns.tokenizer
import dns.wire

# Until there is an RFC, this module is experimental and may be changed in
# incompatible ways.


class UnknownDelegInfoKey(dns.exception.DNSException):
    """Unknown DelegInfoKey"""


class DelegInfoKey(dns.enum.IntEnum):
    """DelegInfoKey"""

    SERVER_IPV4 = 1
    SERVER_IPV6 = 2
    SERVER_NAME = 3
    INCLUDE_DELEGI = 4
    ALPN = 65280
    DOHPATH = 65281
    PORT = 65282
    HOSTNAME = 65283

    @classmethod
    def _maximum(cls):
        return 65535

    @classmethod
    def _short_name(cls):
        return "DelegInfoKey"

    @classmethod
    def _prefix(cls):
        return "KEY"

    @classmethod
    def _unknown_exception_class(cls):
        return UnknownDelegInfoKey


class Emptiness(enum.IntEnum):
    NEVER = 0
    ALWAYS = 1
    ALLOWED = 2


def _validate_key(key):
    force_generic = False
    if isinstance(key, bytes):
        # We decode to latin-1 so we get 0-255 as valid and do NOT interpret
        # UTF-8 sequences
        key = key.decode("latin-1")
    if isinstance(key, str):
        if key.lower().startswith("key"):
            force_generic = True
            if key[3:].startswith("0") and len(key) != 4:
                # key has leading zeros
                raise ValueError("leading zeros in key")
        key = key.replace("-", "_")
    return (DelegInfoKey.make(key), force_generic)


def key_to_text(key):
    return DelegInfoKey.to_text(key).replace("_", "-").lower()


# Like rdata escapify, but escapes ',' too.

_escaped = b'",\\'


def _escapify(qstring):
    text = ""
    for c in qstring:
        if c in _escaped:
            text += "\\" + chr(c)
        elif c >= 0x20 and c < 0x7F:
            text += chr(c)
        else:
            text += f"\\{c:03d}"
    return text


def _unescape(value: str) -> bytes:
    if value == "":
        return b""
    unescaped = b""
    l = len(value)
    i = 0
    while i < l:
        c = value[i]
        i += 1
        if c == "\\":
            if i >= l:  # pragma: no cover   (can't happen via tokenizer get())
                raise dns.exception.UnexpectedEnd
            c = value[i]
            i += 1
            if c.isdigit():
                if i >= l:
                    raise dns.exception.UnexpectedEnd
                c2 = value[i]
                i += 1
                if i >= l:
                    raise dns.exception.UnexpectedEnd
                c3 = value[i]
                i += 1
                if not (c2.isdigit() and c3.isdigit()):
                    raise dns.exception.SyntaxError
                codepoint = int(c) * 100 + int(c2) * 10 + int(c3)
                if codepoint > 255:
                    raise dns.exception.SyntaxError
                unescaped += b"%c" % (codepoint)
                continue
        unescaped += c.encode()
    return unescaped


def _split(value):
    l = len(value)
    i = 0
    items = []
    unescaped = b""
    while i < l:
        c = value[i]
        i += 1
        if c == ord("\\"):
            if i >= l:  # pragma: no cover   (can't happen via tokenizer get())
                raise dns.exception.UnexpectedEnd
            c = value[i]
            i += 1
            unescaped += b"%c" % (c)
        elif c == ord(","):
            items.append(unescaped)
            unescaped = b""
        else:
            unescaped += b"%c" % (c)
    items.append(unescaped)
    return items


@dns.immutable.immutable
class DelegInfo:
    """Abstract base class for DELEG infos"""

    @classmethod
    def emptiness(cls) -> Emptiness:
        return Emptiness.NEVER


@dns.immutable.immutable
class GenericInfo(DelegInfo):
    """Generic DELEG info"""

    def __init__(self, value):
        self.value = dns.rdata.Rdata._as_bytes(value, True)

    @classmethod
    def emptiness(cls):
        return Emptiness.ALLOWED

    @classmethod
    def from_value(cls, value):
        if value is None or len(value) == 0:
            return None
        else:
            return cls(_unescape(value))

    def to_text(self):
        return '"' + dns.rdata._escapify(self.value) + '"'

    @classmethod
    def from_wire_parser(cls, parser, origin=None):  # pylint: disable=W0613
        value = parser.get_bytes(parser.remaining())
        if len(value) == 0:
            return None
        else:
            return cls(value)

    def to_wire(self, file, origin=None):  # pylint: disable=W0613
        file.write(self.value)


@dns.immutable.immutable
class ServerIPv4Info(DelegInfo):
    def __init__(self, addresses):
        self.addresses = dns.rdata.Rdata._as_tuple(
            addresses, dns.rdata.Rdata._as_ipv4_address
        )

    @classmethod
    def from_value(cls, value):
        addresses = value.split(",")
        return cls(addresses)

    def to_text(self):
        return '"' + ",".join(self.addresses) + '"'

    @classmethod
    def from_wire_parser(cls, parser, origin=None):  # pylint: disable=W0613
        addresses = []
        while parser.remaining() > 0:
            ip = parser.get_bytes(4)
            addresses.append(dns.ipv4.inet_ntoa(ip))
        return cls(addresses)

    def to_wire(self, file, origin=None):  # pylint: disable=W0613
        for address in self.addresses:
            file.write(dns.ipv4.inet_aton(address))


@dns.immutable.immutable
class ServerIPv6Info(DelegInfo):
    def __init__(self, addresses):
        self.addresses = dns.rdata.Rdata._as_tuple(
            addresses, dns.rdata.Rdata._as_ipv6_address
        )

    @classmethod
    def from_value(cls, value):
        addresses = value.split(",")
        return cls(addresses)

    def to_text(self):
        return '"' + ",".join(self.addresses) + '"'

    @classmethod
    def from_wire_parser(cls, parser, origin=None):  # pylint: disable=W0613
        addresses = []
        while parser.remaining() > 0:
            ip = parser.get_bytes(16)
            addresses.append(dns.ipv6.inet_ntoa(ip))
        return cls(addresses)

    def to_wire(self, file, origin=None):  # pylint: disable=W0613
        for address in self.addresses:
            file.write(dns.ipv6.inet_aton(address))


def _bytes_as_string(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode()
    else:
        return value


def _escapify_commas(value: str) -> str:
    return value.replace(",", "\\,")


@dns.immutable.immutable
class NameSetInfo(DelegInfo):
    def __init__(self, names):
        self.names = dns.rdata.Rdata._as_tuple(
            names, lambda x: dns.rdata.Rdata._as_name(_bytes_as_string(x))
        )
        if len(set(self.names)) != len(self.names):
            raise ValueError("duplicate name in a NameSetInfo")

    @classmethod
    def from_value(cls, value):
        return cls(_split(_unescape(value)))

    def to_text(self):
        value = ",".join(
            [
                _escapify_commas(dns.rdata._escapify(name.to_text().encode()))
                for name in self.names
            ]
        )
        return '"' + dns.rdata._escapify(value.encode()) + '"'

    @classmethod
    def from_wire_parser(cls, parser, origin=None):  # pylint: disable=W0613
        names = []
        while parser.remaining() > 0:
            name = parser.get_name()
            names.append(name)
        return cls(names)

    def to_wire(self, file, origin=None):  # pylint: disable=W0613
        for name in self.names:
            name.to_wire(file, None, None, False)


@dns.immutable.immutable
class ALPNInfo(DelegInfo):
    def __init__(self, ids):
        self.ids = dns.rdata.Rdata._as_tuple(
            ids, lambda x: dns.rdata.Rdata._as_bytes(x, True, 255, False)
        )

    @classmethod
    def from_value(cls, value):
        return cls(_split(_unescape(value)))

    def to_text(self):
        value = ",".join([_escapify(id) for id in self.ids])
        return '"' + dns.rdata._escapify(value.encode()) + '"'

    @classmethod
    def from_wire_parser(cls, parser, origin=None):  # pylint: disable=W0613
        ids = []
        while parser.remaining() > 0:
            id = parser.get_counted_bytes()
            ids.append(id)
        return cls(ids)

    def to_wire(self, file, origin=None):  # pylint: disable=W0613
        for id in self.ids:
            file.write(struct.pack("!B", len(id)))
            file.write(id)


@dns.immutable.immutable
class PortInfo(DelegInfo):
    def __init__(self, port):
        self.port = dns.rdata.Rdata._as_uint16(port)

    @classmethod
    def from_value(cls, value):
        value = int(value)
        return cls(value)

    def to_text(self):
        return f'"{self.port}"'

    @classmethod
    def from_wire_parser(cls, parser, origin=None):  # pylint: disable=W0613
        port = parser.get_uint16()
        return cls(port)

    def to_wire(self, file, origin=None):  # pylint: disable=W0613
        file.write(struct.pack("!H", self.port))


@dns.immutable.immutable
class NameInfo(DelegInfo):
    def __init__(self, name):
        self.name = dns.rdata.Rdata._as_name(_bytes_as_string(name))

    @classmethod
    def from_value(cls, value):
        return cls(_unescape(value))

    def to_text(self):
        value = self.name.to_text()
        return '"' + dns.rdata._escapify(value.encode()) + '"'

    @classmethod
    def from_wire_parser(cls, parser, origin=None):  # pylint: disable=W0613
        name = parser.get_name()
        return cls(name)

    def to_wire(self, file, origin=None):  # pylint: disable=W0613
        self.name.to_wire(file, None, None, False)


_class_for_key: Dict[DelegInfoKey, Any] = {
    DelegInfoKey.SERVER_IPV4: ServerIPv4Info,
    DelegInfoKey.SERVER_IPV6: ServerIPv6Info,
    DelegInfoKey.SERVER_NAME: NameSetInfo,
    DelegInfoKey.INCLUDE_DELEGI: NameSetInfo,
    DelegInfoKey.ALPN: ALPNInfo,
    DelegInfoKey.PORT: PortInfo,
    DelegInfoKey.HOSTNAME: NameInfo,
}


def _validate_and_define(infos, key, value):
    (key, force_generic) = _validate_key(_unescape(key))
    if key in infos:
        raise SyntaxError(f'duplicate key "{key:d}"')
    cls = _class_for_key.get(key, GenericInfo)
    emptiness = cls.emptiness()
    if value is None:
        if emptiness == Emptiness.NEVER:
            raise SyntaxError("value cannot be empty")
        value = cls.from_value(value)
    else:
        if force_generic:
            value = cls.from_wire_parser(dns.wire.Parser(_unescape(value)))
        else:
            value = cls.from_value(value)
    infos[key] = value


@dns.immutable.immutable
class DelegBase(dns.rdata.Rdata):
    """Base class for DELEG-like records"""

    # see: draft-ietf-deleg-03.txt

    __slots__ = ["infos"]

    def __init__(self, rdclass, rdtype, infos):
        super().__init__(rdclass, rdtype)
        for k, v in infos.items():
            k = DelegInfoKey.make(k)
            if not isinstance(v, DelegInfo) and v is not None:
                raise ValueError(f"{k:d} not a DelegInfo")
        have_v4 = infos.get(DelegInfoKey.SERVER_IPV4)
        have_v6 = infos.get(DelegInfoKey.SERVER_IPV6)
        have_server_name = infos.get(DelegInfoKey.SERVER_NAME)
        have_include = infos.get(DelegInfoKey.INCLUDE_DELEGI)
        if (have_v4 or have_v6) and (have_server_name or have_include):
            raise ValueError(
                "an address DELEG cannot have a server-name or include-delegi"
            )
        elif have_server_name and have_include:
            raise ValueError("a server-name DELEG cannot have an include-delegi")
        self.infos = dns.immutable.Dict(infos)

    def to_text(self, origin=None, relativize=True, **kw):
        infos = []
        for key in sorted(self.infos.keys()):
            value = self.infos[key]
            if value is None:
                infos.append(key_to_text(key))
            else:
                kv = key_to_text(key) + "=" + value.to_text()
                infos.append(kv)
        return " ".join(infos)

    @classmethod
    def from_text(
        cls, rdclass, rdtype, tok, origin=None, relativize=True, relativize_to=None
    ):
        infos = {}
        while True:
            token = tok.get()
            if token.is_eol_or_eof():
                tok.unget(token)
                break
            if token.ttype != dns.tokenizer.IDENTIFIER:
                raise SyntaxError("info is not an identifier")
            equals = token.value.find("=")
            if equals == len(token.value) - 1:
                # 'key=', so next token should be a quoted string without
                # any intervening whitespace.
                key = token.value[:-1]
                token = tok.get(want_leading=True)
                if token.ttype != dns.tokenizer.QUOTED_STRING:
                    raise SyntaxError("whitespace after =")
                value = token.value
            elif equals > 0:
                # key=value
                key = token.value[:equals]
                value = token.value[equals + 1 :]
            elif equals == 0:
                # =key
                raise SyntaxError('info cannot start with "="')
            else:
                # key
                key = token.value
                value = None
            _validate_and_define(infos, key, value)
        return cls(rdclass, rdtype, infos)

    def _to_wire(self, file, compress=None, origin=None, canonicalize=False):
        for key in sorted(self.infos):
            file.write(struct.pack("!H", key))
            value = self.infos[key]
            with dns.renderer.prefixed_length(file, 2):
                # Note that we're still writing a length of zero if the value is None
                if value is not None:
                    value.to_wire(file, origin)

    @classmethod
    def from_wire_parser(cls, rdclass, rdtype, parser, origin=None):
        infos = {}
        prior_key = -1
        while parser.remaining() > 0:
            key = parser.get_uint16()
            if key < prior_key:
                raise dns.exception.FormError("keys not in order")
            prior_key = key
            vlen = parser.get_uint16()
            pkey = DelegInfoKey.make(key)
            pcls = _class_for_key.get(pkey, GenericInfo)
            with parser.restrict_to(vlen):
                value = pcls.from_wire_parser(parser, origin)
            infos[pkey] = value
        return cls(rdclass, rdtype, infos)
