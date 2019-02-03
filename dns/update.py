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

"""DNS Dynamic Update Support"""


import struct
import dns.messagebase
import dns.message
import dns.name
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.tsig
from ._compat import xrange, string_types
from dns.exception import FormError


#: The question section number
ZONE = 0

#: The answer section number
PREREQ = 1

#: The authority section number
UPDATE = 2

#: The additional section number
ADDITIONAL = 3


class Update(dns.messagebase.MessageBase):

    def __init__(self, zone=None, rdclass=dns.rdataclass.IN, keyring=None,
                 keyname=None, keyalgorithm=dns.tsig.default_algorithm):
        """Initialize a new DNS Update object.

        See the documentation of the Message class for a complete
        description of the keyring dictionary.

        *zone*, a ``dns.name.Name`` or ``str``, the zone which is being
        updated.

        *rdclass*, an ``int`` or ``str``, the class of the zone.

        *keyring*, a ``dict``, the TSIG keyring to use.  If a
        *keyring* is specified but a *keyname* is not, then the key
        used will be the first key in the *keyring*.  Note that the
        order of keys in a dictionary is not defined, so applications
        should supply a keyname when a keyring is used, unless they
        know the keyring contains only one key.

        *keyname*, a ``dns.name.Name`` or ``None``, the name of the TSIG key
        to use; defaults to ``None``. The key must be defined in the keyring.

        *keyalgorithm*, a ``dns.name.Name``, the TSIG algorithm to use.
        """
        super(Update, self).__init__()

        # create the sections
        self.zone = []
        self.prereq = []
        self.update = []
        self.additional = []

        # set this to be an update message
        self.flags |= dns.opcode.to_flags(dns.opcode.UPDATE)

        # if zone supplied, setup the zone section
        if zone:
            if isinstance(zone, string_types):
                zone = dns.name.from_text(zone)
            self.zone_name = zone
            self.find_rrset(self.zone, self.zone_name, rdclass, dns.rdatatype.SOA,
                            create=True, force_unique=True)

        # if zone rdata class supplied, store it
        if rdclass:
            if isinstance(rdclass, string_types):
                rdclass = dns.rdataclass.from_text(rdclass)
            self.zone_rdclass = rdclass

        # if keyring is supplied, set it up
        if keyring:
            self.use_tsig(keyring, keyname, algorithm=keyalgorithm)

    def _add_rr(self, name, ttl, rd, deleting=None, section=None):
        """Add a single RR to the update section."""

        if section is None:
            section = self.update
        covers = rd.covers()
        rrset = self.find_rrset(section, name, self.zone_rdclass, rd.rdtype,
                                covers, deleting, True, True)
        rrset.add(rd, ttl)

    def _add(self, replace, section, name, *args):
        """Add records.

        *replace* is the replacement mode.  If ``False``,
        RRs are added to an existing RRset; if ``True``, the RRset
        is replaced with the specified contents.  The second
        argument is the section to add to.  The third argument
        is always a name.  The other arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if isinstance(args[0], dns.rdataset.Rdataset):
            for rds in args:
                if replace:
                    self.delete(name, rds.rdtype)
                for rd in rds:
                    self._add_rr(name, rds.ttl, rd, section=section)
        else:
            args = list(args)
            ttl = int(args.pop(0))
            if isinstance(args[0], dns.rdata.Rdata):
                if replace:
                    self.delete(name, args[0].rdtype)
                for rd in args:
                    self._add_rr(name, ttl, rd, section=section)
            else:
                rdtype = dns.rdatatype.RdataType.make(args.pop(0))
                if replace:
                    self.delete(name, rdtype)
                for s in args:
                    rd = dns.rdata.from_text(self.zone_rdclass, rdtype, s,
                                             self.zone_name)
                    self._add_rr(name, ttl, rd, section=section)

    def add(self, name, *args):
        """Add records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """

        self._add(False, self.authority, name, *args)

    def delete(self, name, *args):
        """Delete records.

        The first argument is always a name.  The other
        arguments can be:

                - *empty*

                - rdataset...

                - rdata...

                - rdtype, [string...]
        """

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            self.find_rrset(self.authority, name, dns.rdataclass.ANY,
                            dns.rdatatype.ANY, dns.rdatatype.NONE,
                            dns.rdatatype.ANY, True, True)
        elif isinstance(args[0], dns.rdataset.Rdataset):
            for rds in args:
                for rd in rds:
                    self._add_rr(name, 0, rd, dns.rdataclass.NONE)
        else:
            args = list(args)
            if isinstance(args[0], dns.rdata.Rdata):
                for rd in args:
                    self._add_rr(name, 0, rd, dns.rdataclass.NONE)
            else:
                rdtype = dns.rdatatype.RdataType.make(args.pop(0))
                if len(args) == 0:
                    self.find_rrset(self.authority, name,
                                    self.zone_rdclass, rdtype,
                                    dns.rdatatype.NONE,
                                    dns.rdataclass.ANY,
                                    True, True)
                else:
                    for s in args:
                        rd = dns.rdata.from_text(self.zone_rdclass, rdtype, s,
                                                 self.zone_name)
                        self._add_rr(name, 0, rd, dns.rdataclass.NONE)

    def replace(self, name, *args):
        """Replace records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...

        Note that if you want to replace the entire node, you should do
        a delete of the name followed by one or more calls to add.
        """

        self._add(True, self.authority, name, *args)

    def present(self, name, *args):
        """Require that an owner name (and optionally an rdata type,
        or specific rdataset) exists as a prerequisite to the
        execution of the update.

        The first argument is always a name.
        The other arguments can be:

                - rdataset...

                - rdata...

                - rdtype, string...
        """

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            self.find_rrset(self.answer, name,
                            dns.rdataclass.ANY, dns.rdatatype.ANY,
                            dns.rdatatype.NONE, None,
                            True, True)
        elif isinstance(args[0], dns.rdataset.Rdataset) or \
            isinstance(args[0], dns.rdata.Rdata) or \
                len(args) > 1:
            if not isinstance(args[0], dns.rdataset.Rdataset):
                # Add a 0 TTL
                args = list(args)
                args.insert(0, 0)
            self._add(False, self.answer, name, *args)
        else:
            rdtype = dns.rdatatype.RdataType.make(args[0])
            self.find_rrset(self.answer, name,
                            dns.rdataclass.ANY, rdtype,
                            dns.rdatatype.NONE, None,
                            True, True)

    def absent(self, name, rdtype=None):
        """Require that an owner name (and optionally an rdata type) does
        not exist as a prerequisite to the execution of the update."""

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if rdtype is None:
            self.find_rrset(self.answer, name,
                            dns.rdataclass.NONE, dns.rdatatype.ANY,
                            dns.rdatatype.NONE, None,
                            True, True)
        else:
            rdtype = dns.rdatatype.RdataType.make(rdtype)
            self.find_rrset(self.answer, name,
                            dns.rdataclass.NONE, rdtype,
                            dns.rdatatype.NONE, None,
                            True, True)

    def to_wire(self, origin=None, max_size=65535):
        """Return a string containing the update in DNS compressed wire
        format.

        *origin*, a ``dns.name.Name`` or ``None``, the origin to be
        appended to any relative names.  If *origin* is ``None``, then
        the origin of the ``dns.update.Update`` message object is used
        (i.e. the *zone* parameter passed when the Update object was
        created).

        *max_size*, an ``int``, the maximum size of the wire format
        output; default is 0, which means "the message's request
        payload, if nonzero, or 65535".

        Returns a ``bytes``.
        """

        if origin is None:
            origin = self.origin
        return super(Update, self).to_wire(origin, max_size)

    def section_number(self, section):
        """Return the "section number" of the specified section for use
        in indexing.  The question section is 0, the answer section is 1,
        the authority section is 2, and the additional section is 3.

        *section* is one of the section attributes of this message.

        Raises ``ValueError`` if the section isn't known.

        Returns an ``int``.
        """

        if section is self.zone:
            return ZONE
        elif section is self.prereq:
            return PREREQ
        elif section is self.update:
            return UPDATE
        elif section is self.additional:
            return ADDITIONAL
        else:
            raise ValueError('unknown section')

    def section_from_number(self, number):
        """Return the "section number" of the specified section for use
        in indexing.  The question section is 0, the answer section is 1,
        the authority section is 2, and the additional section is 3.

        *section* is one of the section attributes of this message.

        Raises ``ValueError`` if the section isn't known.

        Returns an ``int``.
        """

        if number == ZONE:
            return self.zone
        elif number == PREREQ:
            return self.prereq
        elif number == UPDATE:
            return self.update
        elif number == ADDITIONAL:
            return self.additional
        else:
            raise ValueError('unknown section')

    def section_name_from_number(self, number):
        """Return the "section number" of the specified section for use
        in indexing.  The question section is 0, the answer section is 1,
        the authority section is 2, and the additional section is 3.

        *section* is one of the section attributes of this message.

        Raises ``ValueError`` if the section isn't known.

        Returns an ``int``.
        """

        if number == ZONE:
            return "ZONE"
        elif number == PREREQ:
            return "PREREQ"
        elif number == UPDATE:
            return "UPDATE"
        elif number == ADDITIONAL:
            return "ADDITIONAL"
        else:
            raise ValueError('unknown section')


class _WireReader(dns.messagebase._WireReader):
    def __init__(self,  wire, message, ignore_trailing=False):
        super(_WireReader, self).__init__(wire, message, False, False,
                                          ignore_trailing)

    def _get_zone(self, zcount):
        """Read the next *zcount* records from the wire data and add them to
        the zone section.
        """
        self._get_firstsection(self.message.zone, zcount)

    def _get_prereq_section(self, pcount):
        for i in xrange(0, pcount):
            (name, used) = dns.name.from_wire(self.wire, self.current)
            self.current = self.current + used
            (rdtype, rdclass, ttl, rdlen) = \
                struct.unpack('!HHIH',
                              self.wire[self.current:self.current + 10])
            self.current = self.current + 10

            if rdtype == dns.rdatatype.OPT or rdtype == dns.rdatatype.TSIG:
                raise FormError

            # don't create Rdatas for ANY/NONE
            if rdclass == dns.rdataclass.ANY or rdclass == dns.rdataclass.NONE:
                rd = None
            else:
                rd = dns.rdata.from_wire(rdclass, rdtype, self.wire,
                                         self.current, rdlen,
                                         self.message.zone_name)

            # always create the RRset, but only add Rdatas to it if the
            # Rdata class matched above
            rrset = self.message.find_rrset(self.message.prereq, name,
                                            rdclass, rdtype,
                                            create=True)
            if rd:
                rrset.add(rd, ttl)

            self.current = self.current + rdlen

    def read(self):
        """Read a wire format DNS update message."""
        (self.message.id, self.message.flags, zcount, pcount,
         ucount, adcount) = self._get_header()

        # parse, per RFC 2136:
        # 3.1.1. The Zone Section is checked to see that there is
        # exactly one RR therein and that the RR's ZTYPE is SOA, else
        # signal FORMERR to the requestor
        if zcount != 1:
            raise FormError("update message must have exactly 1 zone")
        self._get_zone(zcount)

        for rrset in self.message.zone:
            if rrset.rdtype != dns.rdatatype.SOA:
                raise FormError("update message zone type must be SOA")

            # get the zone
            self.message.zone_name = rrset.name

        # read the remaining sections
        self._get_prereq_section(pcount)
        self._get_section(self.message.update, ucount)
        self._get_section(self.message.additional, adcount)
        self._get_trailer()


def from_wire(wire, keyring=None, request_mac=b'', origin=None, tsig_ctx=None,
              multi=False, first=True, ignore_trailing=False):
    """Convert a DNS wire format message into a message
    object.

    *keyring*, a ``dict``, the keyring to use if the message is signed.

    *request_mac*, a ``binary``.  If the message is a response to a
    TSIG-signed request, *request_mac* should be set to the MAC of
    that request.

    *origin*, a ``dns.name.Name`` or ``None``.  If the message is part
    of a zone transfer, *origin* should be the origin name of the
    zone.

    *tsig_ctx*, a ``hmac.HMAC`` objext, the ongoing TSIG context, used
    when validating zone transfers.

    *multi*, a ``bool``, should be set to ``True`` if this message
    part of a multiple message sequence.

    *first*, a ``bool``, should be set to ``True`` if this message is
    stand-alone, or the first message in a multi-message sequence.

   *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the message.

    Raises ``dns.message.ShortHeader`` if the message is less than 12 octets
    long.

    Raises ``dns.messaage.TrailingJunk`` if there were octets in the message
    past the end of the proper DNS message, and *ignore_trailing* is ``False``.

    Raises ``dns.message.BadEDNS`` if an OPT record was in the
    wrong section, or occurred more than once.

    Raises ``dns.message.BadTSIG`` if a TSIG record was not the last
    record of the additional data section.

    Returns a ``dns.update.Update``.
    """

    u = Update()
    u.keyring = keyring
    u.request_mac = request_mac
    u.origin = origin
    u.tsig_ctx = tsig_ctx
    u.multi = multi
    u.first = first

    reader = _WireReader(wire, u, ignore_trailing)
    reader.read()

    return u


class _TextReader(dns.messagebase._TextReader):
    def __init__(self, text, message):
        super(_TextReader, self).__init__(text, message)

    def read(self):
        """Read a text format DNS message and build a dns.message.Message
        object."""

        line_method = self._header_line
        section = None
        while 1:
            token = self.tok.get(True, True)
            if token.is_eol_or_eof():
                break
            if token.is_comment():
                u = token.value.upper()
                if u == 'HEADER':
                    line_method = self._header_line
                elif u == 'ZONE':
                    line_method = self._question_line
                    section = self.message.question
                elif u == 'PREREQ':
                    line_method = self._rr_line
                    section = self.message.answer
                elif u == 'UPDATE':
                    line_method = self._rr_line
                    section = self.message.authority
                elif u == 'ADDITIONAL':
                    line_method = self._rr_line
                    section = self.message.additional
                self.tok.get_eol()
                continue
            self.tok.unget(token)
            line_method(section)


def from_text(text):
    """Convert the text format message into a message object.

    *text*, a ``text``, the text format message.

    Raises ``dns.message.UnknownHeaderField`` if a header is unknown.

    Raises ``dns.exception.SyntaxError`` if the text is badly formed.

    Returns a ``dns.update.Update object``
    """

    # 'text' can also be a file, but we don't publish that fact
    # since it's an implementation detail.  The official file
    # interface is from_file().

    u = Update()

    reader = dns.messagebase._TextReader(text, u)
    reader.read()

    return u


def make_response(query, recursion_available=False, our_payload=8192,
                  fudge=300):
    """Make a message which is a response for the specified query.
    The message returned is really a response skeleton; it has all
    of the infrastructure required of a response, but none of the
    content.

    The response's question section is a shallow copy of the query's
    question section, so the query's question RRsets should not be
    changed.

    *query*, a ``dns.message.Message``, the query to respond to.

    *recursion_available*, a ``bool``, should RA be set in the response?

    *our_payload*, an ``int``, the payload size to advertise in EDNS
    responses.

    *fudge*, an ``int``, the TSIG time fudge.

    Returns a ``dns.message.Message`` object.
    """

    if query.flags & dns.flags.QR:
        raise dns.exception.FormError('specified query message is not a query')
    response = dns.message.Message(query.id)
    response.flags = dns.flags.QR | (query.flags & dns.flags.RD)
    if recursion_available:
        response.flags |= dns.flags.RA
    response.set_opcode(query.opcode())
    response.zone = list(query.zone)
    if query.edns >= 0:
        response.use_edns(0, 0, our_payload, query.payload)
    if query.had_tsig:
        response.use_tsig(query.keyring, query.keyname, fudge, None, 0, b'',
                          query.keyalgorithm)
        response.request_mac = query.mac
    return response
