# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2001-2017 Nominum, Inc.
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

"""DNS Messages"""

import contextlib
import io
import struct
import time

import dns.edns
import dns.exception
import dns.flags
import dns.name
import dns.opcode
import dns.entropy
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.renderer
import dns.tsig
import dns.wiredata
import dns.messagebase

#: The question section number
QUESTION = 0

#: The answer section number
ANSWER = 1

#: The authority section number
AUTHORITY = 2

#: The additional section number
ADDITIONAL = 3


class Message(dns.messagebase.MessageBase):
    """A DNS message."""

    def __init__(self, id=None):
        super(Message, self).__init__(id)
        self.question = []
        self.answer = []
        self.authority = []
        self.additional = []

    def __repr__(self):
        return '<DNS message, ID ' + repr(self.id) + '>'

    def is_response(self, other):
        """Is *other* a response this message?

        Returns a ``bool``.
        """

        if other.flags & dns.flags.QR == 0 or \
           self.id != other.id or \
           dns.opcode.from_flags(self.flags) != \
           dns.opcode.from_flags(other.flags):
            return False
        if dns.rcode.from_flags(other.flags, other.ednsflags) != \
                dns.rcode.NOERROR:
            return True
        if dns.opcode.is_update(self.flags):
            # This is assuming the "sender doesn't include anything
            # from the update", but we don't care to check the other
            # case, which is that all the sections are returned and
            # identical.
            return True
        for n in self.question:
            if n not in other.question:
                return False
        for n in other.question:
            if n not in self.question:
                return False
        return True

    def section_number(self, section):
        """Return the "section number" of the specified section for use
        in indexing.  The question section is 0, the answer section is 1,
        the authority section is 2, and the additional section is 3.

        *section* is one of the section attributes of this message.

        Raises ``ValueError`` if the section isn't known.

        Returns an ``int``.
        """

        if section is self.question:
            return QUESTION
        elif section is self.answer:
            return ANSWER
        elif section is self.authority:
            return AUTHORITY
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

        if number == QUESTION:
            return self.question
        elif number == ANSWER:
            return self.answer
        elif number == AUTHORITY:
            return self.authority
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

        if number == QUESTION:
            return "QUESTION"
        elif number == ANSWER:
            return "ANSWER"
        elif number == AUTHORITY:
            return "AUTHORITY"
        elif number == ADDITIONAL:
            return "ADDITIONAL"
        else:
            raise ValueError('unknown section')


class _WireReader(dns.messagebase._WireReader):
    def __init__(self, wire, message, question_only=False,
                 one_rr_per_rrset=False, ignore_trailing=False):
        super(_WireReader, self).__init__(wire, message, question_only,
                                          one_rr_per_rrset, ignore_trailing)

    def _get_question(self, qcount):
        """Read the next *qcount* records from the wire data and add them to
        the question section.
        """
        self._get_firstsection(self.message.question, qcount)

    def read(self):
        """Read a wire format DNS message and build a dns.message.Message
        object."""
        (self.message.id, self.message.flags, qcount, ancount,
         aucount, adcount) = self._get_header()
        self._get_question(qcount)
        if self.question_only:
            return
        self._get_section(self.message.answer, ancount)
        self._get_section(self.message.authority, aucount)
        self._get_section(self.message.additional, adcount)
        self._get_trailer()


def from_wire(wire, keyring=None, request_mac=b'', xfr=False, origin=None,
              tsig_ctx=None, multi=False, first=True,
              question_only=False, one_rr_per_rrset=False,
              ignore_trailing=False, raise_on_truncation=False):
    """Convert a DNS wire format message into a message
    object.

    *keyring*, a ``dict``, the keyring to use if the message is signed.

    *request_mac*, a ``bytes``.  If the message is a response to a
    TSIG-signed request, *request_mac* should be set to the MAC of
    that request.

    *xfr*, a ``bool``, should be set to ``True`` if this message is part of
    a zone transfer.

    *origin*, a ``dns.name.Name`` or ``None``.  If the message is part
    of a zone transfer, *origin* should be the origin name of the
    zone.

    *tsig_ctx*, a ``hmac.HMAC`` object, the ongoing TSIG context, used
    when validating zone transfers.

    *multi*, a ``bool``, should be set to ``True`` if this message is
    part of a multiple message sequence.

    *first*, a ``bool``, should be set to ``True`` if this message is
    stand-alone, or the first message in a multi-message sequence.

    *question_only*, a ``bool``.  If ``True``, read only up to
    the end of the question section.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, put each RR into its
    own RRset.

    *ignore_trailing*, a ``bool``.  If ``True``, ignore trailing
    junk at end of the message.

    *raise_on_truncation*, a ``bool``.  If ``True``, raise an exception if
    the TC bit is set.

    Raises ``dns.message.ShortHeader`` if the message is less than 12 octets
    long.

    Raises ``dns.message.TrailingJunk`` if there were octets in the message
    past the end of the proper DNS message, and *ignore_trailing* is ``False``.

    Raises ``dns.message.BadEDNS`` if an OPT record was in the
    wrong section, or occurred more than once.

    Raises ``dns.message.BadTSIG`` if a TSIG record was not the last
    record of the additional data section.

    Raises ``dns.message.Truncated`` if the TC flag is set and
    *raise_on_truncation* is ``True``.

    Returns a ``dns.message.Message``.
    """

    m = Message(id=0)
    m.keyring = keyring
    m.request_mac = request_mac
    m.xfr = xfr
    m.origin = origin
    m.tsig_ctx = tsig_ctx
    m.multi = multi
    m.first = first

    reader = _WireReader(wire, m, question_only, one_rr_per_rrset,
                         ignore_trailing)
    try:
        reader.read()
    except dns.exception.FormError:
        if m.flags & dns.flags.TC and raise_on_truncation:
            raise Truncated(message=m)
        else:
            raise
    # Reading a truncated message might not have any errors, so we
    # have to do this check here too.
    if m.flags & dns.flags.TC and raise_on_truncation:
        raise Truncated(message=m)

    return m


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
                elif u == 'QUESTION' or u == 'ZONE':
                    line_method = self._question_line
                    section = self.message.question
                elif u == 'ANSWER' or u == 'PREREQ':
                    line_method = self._rr_line
                    section = self.message.answer
                elif u == 'AUTHORITY' or u == 'UPDATE':
                    line_method = self._rr_line
                    section = self.message.authority
                elif u == 'ADDITIONAL':
                    line_method = self._rr_line
                    section = self.message.additional
                self.tok.get_eol()
                continue
            self.tok.unget(token)
            line_method(section)


def from_text(text, idna_codec=None, one_rr_per_rrset=False):
    """Convert the text format message into a message object.

    The reader stops after reading the first blank line in the input to
    facilitate reading multiple messages from a single file with
    ``dns.message.from_file()``.

    *text*, a ``str``, the text format message.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, then each RR is put
    into its own rrset.  The default is ``False``.

    Raises ``dns.message.UnknownHeaderField`` if a header is unknown.

    Raises ``dns.exception.SyntaxError`` if the text is badly formed.

    Returns a ``dns.message.Message object``
    """

    # 'text' can also be a file, but we don't publish that fact
    # since it's an implementation detail.  The official file
    # interface is from_file().

    m = Message()

    reader = dns.message._TextReader(text, m)
    reader.read()

    return m


def make_query(qname, rdtype, rdclass=dns.rdataclass.IN, use_edns=None,
               want_dnssec=False, ednsflags=None, payload=None,
               request_payload=None, options=None, idna_codec=None):
    """Make a query message.

    The query name, type, and class may all be specified either
    as objects of the appropriate type, or as strings.

    The query will have a randomly chosen query id, and its DNS flags
    will be set to dns.flags.RD.

    qname, a ``dns.name.Name`` or ``str``, the query name.

    *rdtype*, an ``int`` or ``str``, the desired rdata type.

    *rdclass*, an ``int`` or ``str``,  the desired rdata class; the default
    is class IN.

    *use_edns*, an ``int``, ``bool`` or ``None``.  The EDNS level to use; the
    default is None (no EDNS).
    See the description of dns.message.Message.use_edns() for the possible
    values for use_edns and their meanings.

    *want_dnssec*, a ``bool``.  If ``True``, DNSSEC data is desired.

    *ednsflags*, an ``int``, the EDNS flag values.

    *payload*, an ``int``, is the EDNS sender's payload field, which is the
    maximum size of UDP datagram the sender can handle.  I.e. how big
    a response to this message can be.

    *request_payload*, an ``int``, is the EDNS payload size to use when
    sending this message.  If not specified, defaults to the value of
    *payload*.

    *options*, a list of ``dns.edns.Option`` objects or ``None``, the EDNS
    options.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    Returns a ``dns.message.Message``
    """

    if isinstance(qname, str):
        qname = dns.name.from_text(qname, idna_codec=idna_codec)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    rdclass = dns.rdataclass.RdataClass.make(rdclass)
    m = Message()
    m.flags |= dns.flags.RD
    m.find_rrset(m.question, qname, rdclass, rdtype, create=True,
                 force_unique=True)
    # only pass keywords on to use_edns if they have been set to a
    # non-None value.  Setting a field will turn EDNS on if it hasn't
    # been configured.
    kwargs = {}
    if ednsflags is not None:
        kwargs['ednsflags'] = ednsflags
        if use_edns is None:
            use_edns = 0
    if payload is not None:
        kwargs['payload'] = payload
        if use_edns is None:
            use_edns = 0
    if request_payload is not None:
        kwargs['request_payload'] = request_payload
        if use_edns is None:
            use_edns = 0
    if options is not None:
        kwargs['options'] = options
        if use_edns is None:
            use_edns = 0
    kwargs['edns'] = use_edns
    m.use_edns(**kwargs)
    m.want_dnssec(want_dnssec)
    return m


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
    response.question = list(query.question)
    if query.edns >= 0:
        response.use_edns(0, 0, our_payload, query.payload)
    if query.had_tsig:
        response.use_tsig(query.keyring, query.keyname, fudge, None, 0, b'',
                          query.keyalgorithm)
        response.request_mac = query.mac
    return response
