# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
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

"""DNS Zones."""

import re
import sys

import dns.exception
import dns.name
import dns.node
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.tokenizer
import dns.transaction
import dns.ttl
import dns.grange


class UnknownOrigin(dns.exception.DNSException):
    """Unknown origin"""


class Reader:

    """Read a DNS zone file into a transaction."""

    def __init__(self, tok, rdclass, txn, allow_include=False):
        self.tok = tok
        (self.zone_origin, self.relativize, _) = \
            txn.manager.origin_information()
        self.current_origin = self.zone_origin
        self.last_ttl = 0
        self.last_ttl_known = False
        self.default_ttl = 0
        self.default_ttl_known = False
        self.last_name = self.current_origin
        self.zone_rdclass = rdclass
        self.txn = txn
        self.saved_state = []
        self.current_file = None
        self.allow_include = allow_include

    def _eat_line(self):
        while 1:
            token = self.tok.get()
            if token.is_eol_or_eof():
                break

    def _rr_line(self):
        """Process one line from a DNS zone file."""
        # Name
        if self.current_origin is None:
            raise UnknownOrigin
        token = self.tok.get(want_leading=True)
        if not token.is_whitespace():
            self.last_name = self.tok.as_name(token, self.current_origin)
        else:
            token = self.tok.get()
            if token.is_eol_or_eof():
                # treat leading WS followed by EOL/EOF as if they were EOL/EOF.
                return
            self.tok.unget(token)
        name = self.last_name
        if not name.is_subdomain(self.zone_origin):
            self._eat_line()
            return
        if self.relativize:
            name = name.relativize(self.zone_origin)
        token = self.tok.get()
        if not token.is_identifier():
            raise dns.exception.SyntaxError

        # TTL
        ttl = None
        try:
            ttl = dns.ttl.from_text(token.value)
            self.last_ttl = ttl
            self.last_ttl_known = True
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except dns.ttl.BadTTL:
            if self.default_ttl_known:
                ttl = self.default_ttl
            elif self.last_ttl_known:
                ttl = self.last_ttl

        # Class
        try:
            rdclass = dns.rdataclass.from_text(token.value)
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except dns.exception.SyntaxError:
            raise
        except Exception:
            rdclass = self.zone_rdclass
        if rdclass != self.zone_rdclass:
            raise dns.exception.SyntaxError("RR class is not zone's class")
        # Type
        try:
            rdtype = dns.rdatatype.from_text(token.value)
        except Exception:
            raise dns.exception.SyntaxError(
                "unknown rdatatype '%s'" % token.value)
        try:
            rd = dns.rdata.from_text(rdclass, rdtype, self.tok,
                                     self.current_origin, self.relativize,
                                     self.zone_origin)
        except dns.exception.SyntaxError:
            # Catch and reraise.
            raise
        except Exception:
            # All exceptions that occur in the processing of rdata
            # are treated as syntax errors.  This is not strictly
            # correct, but it is correct almost all of the time.
            # We convert them to syntax errors so that we can emit
            # helpful filename:line info.
            (ty, va) = sys.exc_info()[:2]
            raise dns.exception.SyntaxError(
                "caught exception {}: {}".format(str(ty), str(va)))

        if not self.default_ttl_known and rdtype == dns.rdatatype.SOA:
            # The pre-RFC2308 and pre-BIND9 behavior inherits the zone default
            # TTL from the SOA minttl if no $TTL statement is present before the
            # SOA is parsed.
            self.default_ttl = rd.minimum
            self.default_ttl_known = True
            if ttl is None:
                # if we didn't have a TTL on the SOA, set it!
                ttl = rd.minimum

        # TTL check.  We had to wait until now to do this as the SOA RR's
        # own TTL can be inferred from its minimum.
        if ttl is None:
            raise dns.exception.SyntaxError("Missing default TTL value")

        self.txn.add(name, ttl, rd)

    def _parse_modify(self, side):
        # Here we catch everything in '{' '}' in a group so we can replace it
        # with ''.
        is_generate1 = re.compile(r"^.*\$({(\+|-?)(\d+),(\d+),(.)}).*$")
        is_generate2 = re.compile(r"^.*\$({(\+|-?)(\d+)}).*$")
        is_generate3 = re.compile(r"^.*\$({(\+|-?)(\d+),(\d+)}).*$")
        # Sometimes there are modifiers in the hostname. These come after
        # the dollar sign. They are in the form: ${offset[,width[,base]]}.
        # Make names
        g1 = is_generate1.match(side)
        if g1:
            mod, sign, offset, width, base = g1.groups()
            if sign == '':
                sign = '+'
        g2 = is_generate2.match(side)
        if g2:
            mod, sign, offset = g2.groups()
            if sign == '':
                sign = '+'
            width = 0
            base = 'd'
        g3 = is_generate3.match(side)
        if g3:
            mod, sign, offset, width = g3.groups()
            if sign == '':
                sign = '+'
            base = 'd'

        if not (g1 or g2 or g3):
            mod = ''
            sign = '+'
            offset = 0
            width = 0
            base = 'd'

        if base != 'd':
            raise NotImplementedError()

        return mod, sign, offset, width, base

    def _generate_line(self):
        # range lhs [ttl] [class] type rhs [ comment ]
        """Process one line containing the GENERATE statement from a DNS
        zone file."""
        if self.current_origin is None:
            raise UnknownOrigin

        token = self.tok.get()
        # Range (required)
        try:
            start, stop, step = dns.grange.from_text(token.value)
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except Exception:
            raise dns.exception.SyntaxError

        # lhs (required)
        try:
            lhs = token.value
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except Exception:
            raise dns.exception.SyntaxError

        # TTL
        try:
            ttl = dns.ttl.from_text(token.value)
            self.last_ttl = ttl
            self.last_ttl_known = True
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except dns.ttl.BadTTL:
            if not (self.last_ttl_known or self.default_ttl_known):
                raise dns.exception.SyntaxError("Missing default TTL value")
            if self.default_ttl_known:
                ttl = self.default_ttl
            elif self.last_ttl_known:
                ttl = self.last_ttl
        # Class
        try:
            rdclass = dns.rdataclass.from_text(token.value)
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except dns.exception.SyntaxError:
            raise dns.exception.SyntaxError
        except Exception:
            rdclass = self.zone_rdclass
        if rdclass != self.zone_rdclass:
            raise dns.exception.SyntaxError("RR class is not zone's class")
        # Type
        try:
            rdtype = dns.rdatatype.from_text(token.value)
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except Exception:
            raise dns.exception.SyntaxError("unknown rdatatype '%s'" %
                                            token.value)

        # rhs (required)
        rhs = token.value

        # The code currently only supports base 'd', so the last value
        # in the tuple _parse_modify returns is ignored
        lmod, lsign, loffset, lwidth, _ = self._parse_modify(lhs)
        rmod, rsign, roffset, rwidth, _ = self._parse_modify(rhs)
        for i in range(start, stop + 1, step):
            # +1 because bind is inclusive and python is exclusive

            if lsign == '+':
                lindex = i + int(loffset)
            elif lsign == '-':
                lindex = i - int(loffset)

            if rsign == '-':
                rindex = i - int(roffset)
            elif rsign == '+':
                rindex = i + int(roffset)

            lzfindex = str(lindex).zfill(int(lwidth))
            rzfindex = str(rindex).zfill(int(rwidth))

            name = lhs.replace('$%s' % (lmod), lzfindex)
            rdata = rhs.replace('$%s' % (rmod), rzfindex)

            self.last_name = dns.name.from_text(name, self.current_origin,
                                                self.tok.idna_codec)
            name = self.last_name
            if not name.is_subdomain(self.zone_origin):
                self._eat_line()
                return
            if self.relativize:
                name = name.relativize(self.zone_origin)

            try:
                rd = dns.rdata.from_text(rdclass, rdtype, rdata,
                                         self.current_origin, self.relativize,
                                         self.zone_origin)
            except dns.exception.SyntaxError:
                # Catch and reraise.
                raise
            except Exception:
                # All exceptions that occur in the processing of rdata
                # are treated as syntax errors.  This is not strictly
                # correct, but it is correct almost all of the time.
                # We convert them to syntax errors so that we can emit
                # helpful filename:line info.
                (ty, va) = sys.exc_info()[:2]
                raise dns.exception.SyntaxError("caught exception %s: %s" %
                                                (str(ty), str(va)))

            self.txn.add(name, ttl, rd)

    def read(self):
        """Read a DNS zone file and build a zone object.

        @raises dns.zone.NoSOA: No SOA RR was found at the zone origin
        @raises dns.zone.NoNS: No NS RRset was found at the zone origin
        """

        try:
            while 1:
                token = self.tok.get(True, True)
                if token.is_eof():
                    if self.current_file is not None:
                        self.current_file.close()
                    if len(self.saved_state) > 0:
                        (self.tok,
                         self.current_origin,
                         self.last_name,
                         self.current_file,
                         self.last_ttl,
                         self.last_ttl_known,
                         self.default_ttl,
                         self.default_ttl_known) = self.saved_state.pop(-1)
                        continue
                    break
                elif token.is_eol():
                    continue
                elif token.is_comment():
                    self.tok.get_eol()
                    continue
                elif token.value[0] == '$':
                    c = token.value.upper()
                    if c == '$TTL':
                        token = self.tok.get()
                        if not token.is_identifier():
                            raise dns.exception.SyntaxError("bad $TTL")
                        self.default_ttl = dns.ttl.from_text(token.value)
                        self.default_ttl_known = True
                        self.tok.get_eol()
                    elif c == '$ORIGIN':
                        self.current_origin = self.tok.get_name()
                        self.tok.get_eol()
                        if self.zone_origin is None:
                            self.zone_origin = self.current_origin
                        self.txn._set_origin(self.current_origin)
                    elif c == '$INCLUDE' and self.allow_include:
                        token = self.tok.get()
                        filename = token.value
                        token = self.tok.get()
                        if token.is_identifier():
                            new_origin =\
                                dns.name.from_text(token.value,
                                                   self.current_origin,
                                                   self.tok.idna_codec)
                            self.tok.get_eol()
                        elif not token.is_eol_or_eof():
                            raise dns.exception.SyntaxError(
                                "bad origin in $INCLUDE")
                        else:
                            new_origin = self.current_origin
                        self.saved_state.append((self.tok,
                                                 self.current_origin,
                                                 self.last_name,
                                                 self.current_file,
                                                 self.last_ttl,
                                                 self.last_ttl_known,
                                                 self.default_ttl,
                                                 self.default_ttl_known))
                        self.current_file = open(filename, 'r')
                        self.tok = dns.tokenizer.Tokenizer(self.current_file,
                                                           filename)
                        self.current_origin = new_origin
                    elif c == '$GENERATE':
                        self._generate_line()
                    else:
                        raise dns.exception.SyntaxError(
                            "Unknown zone file directive '" + c + "'")
                    continue
                self.tok.unget(token)
                self._rr_line()
        except dns.exception.SyntaxError as detail:
            (filename, line_number) = self.tok.where()
            if detail is None:
                detail = "syntax error"
            ex = dns.exception.SyntaxError(
                "%s:%d: %s" % (filename, line_number, detail))
            tb = sys.exc_info()[2]
            raise ex.with_traceback(tb) from None
