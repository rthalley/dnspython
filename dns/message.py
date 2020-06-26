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
import dns.enum
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


class ShortHeader(dns.exception.FormError):
    """The DNS packet passed to from_wire() is too short."""


class TrailingJunk(dns.exception.FormError):
    """The DNS packet passed to from_wire() has extra junk at the end of it."""


class UnknownHeaderField(dns.exception.DNSException):
    """The header field name was not recognized when converting from text
    into a message."""


class BadEDNS(dns.exception.FormError):
    """An OPT record occurred somewhere other than
    the additional data section."""


class BadTSIG(dns.exception.FormError):
    """A TSIG record occurred somewhere other than the end of
    the additional data section."""


class UnknownTSIGKey(dns.exception.DNSException):
    """A TSIG with an unknown key was received."""


class Truncated(dns.exception.DNSException):
    """The truncated flag is set."""

    supp_kwargs = {'message'}

    def message(self):
        """As much of the message as could be processed.

        Returns a ``dns.message.Message``.
        """
        return self.kwargs['message']


class MessageSection(dns.enum.IntEnum):
    """Message sections"""
    QUESTION = 0
    ANSWER = 1
    AUTHORITY = 2
    ADDITIONAL = 3

    @classmethod
    def _maximum(cls):
        return 3

globals().update(MessageSection.__members__)


class Message:
    """A DNS message."""

    _section_enum = MessageSection

    def __init__(self, id=None):
        if id is None:
            self.id = dns.entropy.random_16()
        else:
            self.id = id
        self.flags = 0
        self.sections = [[], [], [], []]
        self.edns = -1
        self.ednsflags = 0
        self.payload = 0
        self.options = []
        self.request_payload = 0
        self.keyring = None
        self.keyname = None
        self.keyalgorithm = dns.tsig.default_algorithm
        self.request_mac = b''
        self.other_data = b''
        self.tsig_error = 0
        self.fudge = 300
        self.original_id = self.id
        self.mac = b''
        self.xfr = False
        self.origin = None
        self.tsig_ctx = None
        self.had_tsig = False
        self.multi = False
        self.first = True
        self.index = {}

    @property
    def question(self):
        """ The question section."""
        return self.sections[0]

    @question.setter
    def question(self, v):
        self.sections[0] = v

    @property
    def answer(self):
        """ The answer section."""
        return self.sections[1]

    @answer.setter
    def answer(self, v):
        self.sections[1] = v

    @property
    def authority(self):
        """ The authority section."""
        return self.sections[2]

    @authority.setter
    def authority(self, v):
        self.sections[2] = v

    @property
    def additional(self):
        """ The additional data section."""
        return self.sections[3]

    @additional.setter
    def additional(self, v):
        self.sections[3] = v

    def __repr__(self):
        return '<DNS message, ID ' + repr(self.id) + '>'

    def __str__(self):
        return self.to_text()

    def to_text(self, origin=None, relativize=True, **kw):
        """Convert the message to text.

        The *origin*, *relativize*, and any other keyword
        arguments are passed to the RRset ``to_wire()`` method.

        Returns a ``str``.
        """

        s = io.StringIO()
        s.write('id %d\n' % self.id)
        s.write('opcode %s\n' %
                dns.opcode.to_text(dns.opcode.from_flags(self.flags)))
        rc = dns.rcode.from_flags(self.flags, self.ednsflags)
        s.write('rcode %s\n' % dns.rcode.to_text(rc))
        s.write('flags %s\n' % dns.flags.to_text(self.flags))
        if self.edns >= 0:
            s.write('edns %s\n' % self.edns)
            if self.ednsflags != 0:
                s.write('eflags %s\n' %
                        dns.flags.edns_to_text(self.ednsflags))
            s.write('payload %d\n' % self.payload)
        for opt in self.options:
            s.write('option %s\n' % opt.to_text())
        for (name, which) in self._section_enum.__members__.items():
            s.write(f';{name}\n')
            for rrset in self.section_from_number(which):
                s.write(rrset.to_text(origin, relativize, **kw))
                s.write('\n')
        #
        # We strip off the final \n so the caller can print the result without
        # doing weird things to get around eccentricities in Python print
        # formatting
        #
        return s.getvalue()[:-1]

    def __eq__(self, other):
        """Two messages are equal if they have the same content in the
        header, question, answer, and authority sections.

        Returns a ``bool``.
        """

        if not isinstance(other, Message):
            return False
        if self.id != other.id:
            return False
        if self.flags != other.flags:
            return False
        for i in range(4):
            section = self.sections[i]
            other_section = other.sections[i]
            for n in section:
                if n not in other_section:
                    return False
            for n in other_section:
                if n not in section:
                    return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

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
        in indexing.

        *section* is one of the section attributes of this message.

        Raises ``ValueError`` if the section isn't known.

        Returns an ``int``.
        """

        for i in range(4):
            if section is self.sections[i]:
                return self._section_enum(i)
        raise ValueError('unknown section')

    def section_from_number(self, number):
        """Return the section list associated with the specified section
        number.

        *number* is a section number `int` or the text form of a section
        name.

        Raises ``ValueError`` if the section isn't known.

        Returns a ``list``.
        """

        section = self._section_enum.make(number)
        return self.sections[section]

    def find_rrset(self, section, name, rdclass, rdtype,
                   covers=dns.rdatatype.NONE, deleting=None, create=False,
                   force_unique=False):
        """Find the RRset with the given attributes in the specified section.

        *section*, an ``int`` section number, or one of the section
        attributes of this message.  This specifies the
        the section of the message to search.  For example::

            my_message.find_rrset(my_message.answer, name, rdclass, rdtype)
            my_message.find_rrset(dns.message.ANSWER, name, rdclass, rdtype)

        *name*, a ``dns.name.Name``, the name of the RRset.

        *rdclass*, an ``int``, the class of the RRset.

        *rdtype*, an ``int``, the type of the RRset.

        *covers*, an ``int`` or ``None``, the covers value of the RRset.
        The default is ``None``.

        *deleting*, an ``int`` or ``None``, the deleting value of the RRset.
        The default is ``None``.

        *create*, a ``bool``.  If ``True``, create the RRset if it is not found.
        The created RRset is appended to *section*.

        *force_unique*, a ``bool``.  If ``True`` and *create* is also ``True``,
        create a new RRset regardless of whether a matching RRset exists
        already.  The default is ``False``.  This is useful when creating
        DDNS Update messages, as order matters for them.

        Raises ``KeyError`` if the RRset was not found and create was
        ``False``.

        Returns a ``dns.rrset.RRset object``.
        """

        if isinstance(section, int):
            section_number = section
            section = self.section_from_number(section_number)
        else:
            section_number = self.section_number(section)
        key = (section_number, name, rdclass, rdtype, covers, deleting)
        if not force_unique:
            if self.index is not None:
                rrset = self.index.get(key)
                if rrset is not None:
                    return rrset
            else:
                for rrset in section:
                    if rrset.match(name, rdclass, rdtype, covers, deleting):
                        return rrset
        if not create:
            raise KeyError
        rrset = dns.rrset.RRset(name, rdclass, rdtype, covers, deleting)
        section.append(rrset)
        if self.index is not None:
            self.index[key] = rrset
        return rrset

    def get_rrset(self, section, name, rdclass, rdtype,
                  covers=dns.rdatatype.NONE, deleting=None, create=False,
                  force_unique=False):
        """Get the RRset with the given attributes in the specified section.

        If the RRset is not found, None is returned.

        *section*, an ``int`` section number, or one of the section
        attributes of this message.  This specifies the
        the section of the message to search.  For example::

            my_message.get_rrset(my_message.answer, name, rdclass, rdtype)
            my_message.get_rrset(dns.message.ANSWER, name, rdclass, rdtype)

        *name*, a ``dns.name.Name``, the name of the RRset.

        *rdclass*, an ``int``, the class of the RRset.

        *rdtype*, an ``int``, the type of the RRset.

        *covers*, an ``int`` or ``None``, the covers value of the RRset.
        The default is ``None``.

        *deleting*, an ``int`` or ``None``, the deleting value of the RRset.
        The default is ``None``.

        *create*, a ``bool``.  If ``True``, create the RRset if it is not found.
        The created RRset is appended to *section*.

        *force_unique*, a ``bool``.  If ``True`` and *create* is also ``True``,
        create a new RRset regardless of whether a matching RRset exists
        already.  The default is ``False``.  This is useful when creating
        DDNS Update messages, as order matters for them.

        Returns a ``dns.rrset.RRset object`` or ``None``.
        """

        try:
            rrset = self.find_rrset(section, name, rdclass, rdtype, covers,
                                    deleting, create, force_unique)
        except KeyError:
            rrset = None
        return rrset

    def to_wire(self, origin=None, max_size=0, multi=False, tsig_ctx=None,
                **kw):
        """Return a string containing the message in DNS compressed wire
        format.

        Additional keyword arguments are passed to the RRset ``to_wire()``
        method.

        *origin*, a ``dns.name.Name`` or ``None``, the origin to be appended
        to any relative names.  If ``None``, and the message has an origin
        attribute that is not ``None``, then it will be used.

        *max_size*, an ``int``, the maximum size of the wire format
        output; default is 0, which means "the message's request
        payload, if nonzero, or 65535".

        *multi*, a ``bool``, should be set to ``True`` if this message is
        part of a multiple message sequence.

        *tsig_ctx*, a ``hmac.HMAC`` object, the ongoing TSIG context, used
        when signing zone transfers.

        Raises ``dns.exception.TooBig`` if *max_size* was exceeded.

        Returns a ``bytes``.
        """

        if origin is None and self.origin is not None:
            origin = self.origin
        if max_size == 0:
            if self.request_payload != 0:
                max_size = self.request_payload
            else:
                max_size = 65535
        if max_size < 512:
            max_size = 512
        elif max_size > 65535:
            max_size = 65535
        r = dns.renderer.Renderer(self.id, self.flags, max_size, origin)
        for rrset in self.question:
            r.add_question(rrset.name, rrset.rdtype, rrset.rdclass)
        for rrset in self.answer:
            r.add_rrset(dns.renderer.ANSWER, rrset, **kw)
        for rrset in self.authority:
            r.add_rrset(dns.renderer.AUTHORITY, rrset, **kw)
        if self.edns >= 0:
            r.add_edns(self.edns, self.ednsflags, self.payload, self.options)
        for rrset in self.additional:
            r.add_rrset(dns.renderer.ADDITIONAL, rrset, **kw)
        r.write_header()
        if self.keyname is not None:
            if multi:
                ctx = r.add_multi_tsig(tsig_ctx,
                                       self.keyname, self.keyring[self.keyname],
                                       self.fudge, self.original_id,
                                       self.tsig_error, self.other_data,
                                       self.request_mac, self.keyalgorithm)
                self.tsig_ctx = ctx
            else:
                r.add_tsig(self.keyname, self.keyring[self.keyname],
                           self.fudge, self.original_id, self.tsig_error,
                           self.other_data, self.request_mac,
                           self.keyalgorithm)
            self.mac = r.mac
        return r.get_wire()

    def use_tsig(self, keyring, keyname=None, fudge=300,
                 original_id=None, tsig_error=0, other_data=b'',
                 algorithm=dns.tsig.default_algorithm):
        """When sending, a TSIG signature using the specified keyring
        and keyname should be added.

        See the documentation of the Message class for a complete
        description of the keyring dictionary.

        *keyring*, a ``dict``, the TSIG keyring to use.  If a
        *keyring* is specified but a *keyname* is not, then the key
        used will be the first key in the *keyring*.  Note that the
        order of keys in a dictionary is not defined, so applications
        should supply a keyname when a keyring is used, unless they
        know the keyring contains only one key.

        *keyname*, a ``dns.name.Name`` or ``None``, the name of the TSIG key
        to use; defaults to ``None``. The key must be defined in the keyring.

        *fudge*, an ``int``, the TSIG time fudge.

        *original_id*, an ``int``, the TSIG original id.  If ``None``,
        the message's id is used.

        *tsig_error*, an ``int``, the TSIG error code.

        *other_data*, a ``bytes``, the TSIG other data.

        *algorithm*, a ``dns.name.Name``, the TSIG algorithm to use.
        """

        self.keyring = keyring
        if keyname is None:
            self.keyname = list(self.keyring.keys())[0]
        else:
            if isinstance(keyname, str):
                keyname = dns.name.from_text(keyname)
            self.keyname = keyname
        self.keyalgorithm = algorithm
        self.fudge = fudge
        if original_id is None:
            self.original_id = self.id
        else:
            self.original_id = original_id
        self.tsig_error = tsig_error
        self.other_data = other_data

    def use_edns(self, edns=0, ednsflags=0, payload=1280, request_payload=None,
                 options=None):
        """Configure EDNS behavior.

        *edns*, an ``int``, is the EDNS level to use.  Specifying
        ``None``, ``False``, or ``-1`` means "do not use EDNS", and in this case
        the other parameters are ignored.  Specifying ``True`` is
        equivalent to specifying 0, i.e. "use EDNS0".

        *ednsflags*, an ``int``, the EDNS flag values.

        *payload*, an ``int``, is the EDNS sender's payload field, which is the
        maximum size of UDP datagram the sender can handle.  I.e. how big
        a response to this message can be.

        *request_payload*, an ``int``, is the EDNS payload size to use when
        sending this message.  If not specified, defaults to the value of
        *payload*.

        *options*, a list of ``dns.edns.Option`` objects or ``None``, the EDNS
        options.
        """

        if edns is None or edns is False:
            edns = -1
        if edns is True:
            edns = 0
        if request_payload is None:
            request_payload = payload
        if edns < 0:
            ednsflags = 0
            payload = 0
            request_payload = 0
            options = []
        else:
            # make sure the EDNS version in ednsflags agrees with edns
            ednsflags &= 0xFF00FFFF
            ednsflags |= (edns << 16)
            if options is None:
                options = []
        self.edns = edns
        self.ednsflags = ednsflags
        self.payload = payload
        self.options = options
        self.request_payload = request_payload

    def want_dnssec(self, wanted=True):
        """Enable or disable 'DNSSEC desired' flag in requests.

        *wanted*, a ``bool``.  If ``True``, then DNSSEC data is
        desired in the response, EDNS is enabled if required, and then
        the DO bit is set.  If ``False``, the DO bit is cleared if
        EDNS is enabled.
        """

        if wanted:
            if self.edns < 0:
                self.use_edns()
            self.ednsflags |= dns.flags.DO
        elif self.edns >= 0:
            self.ednsflags &= ~dns.flags.DO

    def rcode(self):
        """Return the rcode.

        Returns an ``int``.
        """
        return dns.rcode.from_flags(self.flags, self.ednsflags)

    def set_rcode(self, rcode):
        """Set the rcode.

        *rcode*, an ``int``, is the rcode to set.
        """
        (value, evalue) = dns.rcode.to_flags(rcode)
        self.flags &= 0xFFF0
        self.flags |= value
        self.ednsflags &= 0x00FFFFFF
        self.ednsflags |= evalue
        if self.ednsflags != 0 and self.edns < 0:
            self.edns = 0

    def opcode(self):
        """Return the opcode.

        Returns an ``int``.
        """
        return dns.opcode.from_flags(self.flags)

    def set_opcode(self, opcode):
        """Set the opcode.

        *opcode*, an ``int``, is the opcode to set.
        """
        self.flags &= 0x87FF
        self.flags |= dns.opcode.to_flags(opcode)

    def _get_one_rr_per_rrset(self, value):
        # What the caller picked is fine.
        return value

    def _validate_rrset(self, section, rrset):
        if rrset.rdclass == dns.rdataclass.ANY or \
           rrset.rdclass == dns.rdataclass.NONE:
            raise dns.exception.FormError

    def _finish_section(self, section):
        pass


class QueryMessage(Message):
    pass


class _WireReader:

    """Wire format reader.

    wire: a binary, is the wire-format message.
    message: The message object being built
    current: When building a message object from wire format, this
    variable contains the offset from the beginning of wire of the next octet
    to be read.
    one_rr_per_rrset: Put each RR into its own RRset?
    ignore_trailing: Ignore trailing junk at end of request?
    zone_rdclass: The class of the zone in messages which are
    DNS dynamic updates.
    """

    def __init__(self, wire, message, question_only, one_rr_per_rrset,
                 ignore_trailing):
        self.wire = dns.wiredata.maybe_wrap(wire)
        self.message = message
        self.current = 0
        self.zone_rdclass = dns.rdataclass.IN
        self.question_only = question_only
        self.one_rr_per_rrset = message._get_one_rr_per_rrset(one_rr_per_rrset)
        self.ignore_trailing = ignore_trailing

    def _get_question(self, qcount):
        """Read the next *qcount* records from the wire data and add them to
        the question section.
        """

        for i in range(qcount):
            (qname, used) = dns.name.from_wire(self.wire, self.current)
            if self.message.origin is not None:
                qname = qname.relativize(self.message.origin)
            self.current += used
            (rdtype, rdclass) = \
                struct.unpack('!HH',
                              self.wire[self.current:self.current + 4])
            self.current += 4
            rrset = self.message.find_rrset(self.message.question, qname,
                                            rdclass, rdtype, create=True,
                                            force_unique=True)
        for rrset in self.message.sections[MessageSection.QUESTION]:
            self.message._validate_rrset(MessageSection.QUESTION, rrset)
        self.message._finish_section(MessageSection.QUESTION)

    def _get_section(self, section_number, count):
        """Read the next I{count} records from the wire data and add them to
        the specified section.

        section: the section of the message to which to add records
        count: the number of records to read
        """

        section = self.message.sections[section_number]
        force_unique = self.one_rr_per_rrset
        seen_opt = False
        for i in range(count):
            rr_start = self.current
            (name, used) = dns.name.from_wire(self.wire, self.current)
            absolute_name = name
            if self.message.origin is not None:
                name = name.relativize(self.message.origin)
            self.current += used
            (rdtype, rdclass, ttl, rdlen) = \
                struct.unpack('!HHIH',
                              self.wire[self.current:self.current + 10])
            self.current += 10
            if rdtype == dns.rdatatype.OPT:
                if section is not self.message.additional or seen_opt:
                    raise BadEDNS
                self.message.payload = rdclass
                self.message.ednsflags = ttl
                self.message.edns = (ttl & 0xff0000) >> 16
                self.message.options = []
                current = self.current
                optslen = rdlen
                while optslen > 0:
                    (otype, olen) = \
                        struct.unpack('!HH',
                                      self.wire[current:current + 4])
                    current = current + 4
                    opt = dns.edns.option_from_wire(
                        otype, self.wire, current, olen)
                    self.message.options.append(opt)
                    current = current + olen
                    optslen = optslen - 4 - olen
                seen_opt = True
            elif rdtype == dns.rdatatype.TSIG:
                if not (section is self.message.additional and
                        i == (count - 1)):
                    raise BadTSIG
                if self.message.keyring is None:
                    raise UnknownTSIGKey('got signed message without keyring')
                secret = self.message.keyring.get(absolute_name)
                if secret is None:
                    raise UnknownTSIGKey("key '%s' unknown" % name)
                self.message.keyname = absolute_name
                (self.message.keyalgorithm, self.message.mac) = \
                    dns.tsig.get_algorithm_and_mac(self.wire, self.current,
                                                   rdlen)
                self.message.tsig_ctx = \
                    dns.tsig.validate(self.wire,
                                      absolute_name,
                                      secret,
                                      int(time.time()),
                                      self.message.request_mac,
                                      rr_start,
                                      self.current,
                                      rdlen,
                                      self.message.tsig_ctx,
                                      self.message.multi,
                                      self.message.first)
                self.message.had_tsig = True
            else:
                if ttl > 0x7fffffff:
                    ttl = 0
                if rdclass in (dns.rdataclass.ANY, dns.rdataclass.NONE):
                    deleting = rdclass
                    rdclass = self.zone_rdclass
                else:
                    deleting = None
                if deleting == dns.rdataclass.ANY or \
                   (deleting == dns.rdataclass.NONE and
                        section is self.message.answer):
                    covers = dns.rdatatype.NONE
                    rd = None
                else:
                    rd = dns.rdata.from_wire(rdclass, rdtype, self.wire,
                                             self.current, rdlen,
                                             self.message.origin)
                    covers = rd.covers()
                if self.message.xfr and rdtype == dns.rdatatype.SOA:
                    force_unique = True
                rrset = self.message.find_rrset(section, name,
                                                rdclass, rdtype, covers,
                                                deleting, True, force_unique)
                if rd is not None:
                    rrset.add(rd, ttl)
            self.current += rdlen
        for rrset in self.message.sections[section_number]:
            self.message._validate_rrset(section_number, rrset)
        self.message._finish_section(section_number)

    def read(self):
        """Read a wire format DNS message and build a dns.message.Message
        object."""

        l = len(self.wire)
        if l < 12:
            raise ShortHeader
        (self.message.id, self.message.flags, qcount, ancount,
         aucount, adcount) = struct.unpack('!HHHHHH', self.wire[:12])
        self.current = 12
        self.message.original_id = self.message.id
        self._get_question(qcount)
        if self.question_only:
            return
        self._get_section(MessageSection.ANSWER, ancount)
        self._get_section(MessageSection.AUTHORITY, aucount)
        self._get_section(MessageSection.ADDITIONAL, adcount)
        if not self.ignore_trailing and self.current != l:
            raise TrailingJunk
        if self.message.multi and self.message.tsig_ctx and \
                not self.message.had_tsig:
            self.message.tsig_ctx.update(self.wire)


def _maybe_import_update():
    # We avoid circular imports by doing this here.  We do it in another
    # function as doing it in _message_factory_from_opcode() makes "dns"
    # a local symbol, and the first line fails :)
    import dns.update  # noqa: F401


def _message_factory_from_opcode(opcode):
    if opcode == dns.opcode.QUERY:
        return QueryMessage
    elif opcode == dns.opcode.UPDATE:
        _maybe_import_update()
        return dns.update.UpdateMessage
    else:
        return Message


def _message_factory_from_wire(wire):
    if len(wire) < 12:
        raise ShortHeader
    (flags,) = struct.unpack('!H', wire[2:4])
    opcode = dns.opcode.from_flags(flags)
    return _message_factory_from_opcode(opcode)


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
    zone.  If not ``None``, names will be relativized to the origin.

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

    m = _message_factory_from_wire(wire)(id=0)
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


class _TextReader:

    """Text format reader.

    tok: the tokenizer.
    message: The message object being built.
    zone_rdclass: The class of the zone in messages which are
    DNS dynamic updates.
    last_name: The most recently read name when building a message object.
    one_rr_per_rrset: Put each RR into its own RRset?
    origin: The origin for relative names
    relativize: relativize names?
    relativize_to: the origin to relativize to.
    """

    def __init__(self, text, idna_codec, one_rr_per_rrset=False,
                 origin=None, relativize=True, relativize_to=None):
        self.message = None
        self.tok = dns.tokenizer.Tokenizer(text, idna_codec=idna_codec)
        self.last_name = None
        self.zone_rdclass = dns.rdataclass.IN
        self.one_rr_per_rrset = one_rr_per_rrset
        self.origin = origin
        self.relativize = relativize
        self.relativize_to = relativize_to
        self.id = None
        self.edns = -1
        self.ednsflags = 0
        self.payload = None
        self.rcode = None
        self.opcode = dns.opcode.QUERY
        self.flags = 0

    def _header_line(self, section):
        """Process one line from the text format header section."""

        token = self.tok.get()
        what = token.value
        if what == 'id':
            self.id = self.tok.get_int()
        elif what == 'flags':
            while True:
                token = self.tok.get()
                if not token.is_identifier():
                    self.tok.unget(token)
                    break
                self.flags = self.flags | dns.flags.from_text(token.value)
        elif what == 'edns':
            self.edns = self.tok.get_int()
            self.ednsflags = self.ednsflags | (self.edns << 16)
        elif what == 'eflags':
            if self.edns < 0:
                self.edns = 0
            while True:
                token = self.tok.get()
                if not token.is_identifier():
                    self.tok.unget(token)
                    break
                self.ednsflags = self.ednsflags | \
                    dns.flags.edns_from_text(token.value)
        elif what == 'payload':
            self.payload = self.tok.get_int()
            if self.edns < 0:
                self.edns = 0
        elif what == 'opcode':
            text = self.tok.get_string()
            self.opcode = dns.opcode.from_text(text)
            self.flags = self.flags | dns.opcode.to_flags(self.opcode)
        elif what == 'rcode':
            text = self.tok.get_string()
            self.rcode = dns.rcode.from_text(text)
        else:
            raise UnknownHeaderField
        self.tok.get_eol()

    def _question_line(self, section_number):
        """Process one line from the text format question section."""

        section = self.message.sections[section_number]
        token = self.tok.get(want_leading=True)
        if not token.is_whitespace():
            self.last_name = self.tok.as_name(token, self.message.origin,
                                              self.relativize,
                                              self.relativize_to)
        name = self.last_name
        token = self.tok.get()
        if not token.is_identifier():
            raise dns.exception.SyntaxError
        # Class
        try:
            rdclass = dns.rdataclass.from_text(token.value)
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except dns.exception.SyntaxError:
            raise dns.exception.SyntaxError
        except Exception:
            rdclass = dns.rdataclass.IN
        # Type
        rdtype = dns.rdatatype.from_text(token.value)
        self.message.find_rrset(section, name, rdclass, rdtype, create=True,
                                force_unique=True)
        self.zone_rdclass = rdclass
        self.tok.get_eol()

    def _rr_line(self, section_number):
        """Process one line from the text format answer, authority, or
        additional data sections.
        """

        section = self.message.sections[section_number]
        deleting = None
        # Name
        token = self.tok.get(want_leading=True)
        if not token.is_whitespace():
            self.last_name = self.tok.as_name(token, self.message.origin,
                                              self.relativize,
                                              self.relativize_to)
        name = self.last_name
        token = self.tok.get()
        if not token.is_identifier():
            raise dns.exception.SyntaxError
        # TTL
        try:
            ttl = int(token.value, 0)
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
        except dns.exception.SyntaxError:
            raise dns.exception.SyntaxError
        except Exception:
            ttl = 0
        # Class
        try:
            rdclass = dns.rdataclass.from_text(token.value)
            token = self.tok.get()
            if not token.is_identifier():
                raise dns.exception.SyntaxError
            if rdclass == dns.rdataclass.ANY or rdclass == dns.rdataclass.NONE:
                deleting = rdclass
                rdclass = self.zone_rdclass
        except dns.exception.SyntaxError:
            raise dns.exception.SyntaxError
        except Exception:
            rdclass = dns.rdataclass.IN
        # Type
        rdtype = dns.rdatatype.from_text(token.value)
        token = self.tok.get()
        if not token.is_eol_or_eof():
            self.tok.unget(token)
            rd = dns.rdata.from_text(rdclass, rdtype, self.tok,
                                     self.message.origin, self.relativize,
                                     self.relativize_to)
            covers = rd.covers()
        else:
            rd = None
            covers = dns.rdatatype.NONE
        rrset = self.message.find_rrset(section, name,
                                        rdclass, rdtype, covers,
                                        deleting, True, self.one_rr_per_rrset)
        if rd is not None:
            rrset.add(rd, ttl)

    def _maybe_instantiate_message(self):
        if self.message is None:
            # Time to instantiate the message!
            factory = _message_factory_from_opcode(self.opcode)
            self.message = factory(id=self.id)
            self.message.flags = self.flags
            if self.edns >= 0:
                self.message.edns = self.edns
            if self.ednsflags:
                self.message.ednsflags = self.ednsflags
            if self.payload:
                self.message.payload = self.payload
            if self.rcode:
                self.message.set_rcode(self.rcode)
            self.one_rr_per_rrset = \
                self.message._get_one_rr_per_rrset(self.one_rr_per_rrset)
            if self.origin:
                self.message.origin = self.origin

    def read(self):
        """Read a text format DNS message and build a dns.message.Message
        object."""

        line_method = self._header_line
        section_number = None
        while 1:
            token = self.tok.get(True, True)
            if token.is_eol_or_eof():
                break
            if token.is_comment():
                u = token.value.upper()
                if u == 'HEADER':
                    line_method = self._header_line
                elif u in {'QUESTION', 'ANSWER', 'AUTHORITY', 'ADDITIONAL',
                           'ZONE', 'PREREQ', 'UPDATE'}:
                    # It's ugly, but we have to do the check above because
                    # if the token is JUST a comment, we want to ignore it,
                    # and not prehaps prematurely instantiate the message!
                    self._maybe_instantiate_message()
                    section_number = self.message._section_enum.make(u)
                    if section_number == 0:
                        line_method = self._question_line
                    else:
                        line_method = self._rr_line
                self.tok.get_eol()
                continue
            self.tok.unget(token)
            line_method(section_number)
        for i in range(4):
            for rrset in self.message.sections[i]:
                self.message._validate_rrset(i, rrset)
            self.message._finish_section(i)
        return self.message


def from_text(text, idna_codec=None, one_rr_per_rrset=False,
              origin=None, relativize=True, relativize_to=None):
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

    *origin*, a ``dns.name.Name`` (or ``None``), the
    origin to use for relative names.

    *relativize*, a ``bool``.  If true, name will be relativized.

    *relativize_to*, a ``dns.name.Name`` (or ``None``), the origin to use
    when relativizing names.  If not set, the *origin* value will be used.

    Raises ``dns.message.UnknownHeaderField`` if a header is unknown.

    Raises ``dns.exception.SyntaxError`` if the text is badly formed.

    Returns a ``dns.message.Message object``
    """

    # 'text' can also be a file, but we don't publish that fact
    # since it's an implementation detail.  The official file
    # interface is from_file().

    reader = _TextReader(text, idna_codec, one_rr_per_rrset, origin,
                         relativize, relativize_to)
    return reader.read()


def from_file(f, idna_codec=None, one_rr_per_rrset=False):
    """Read the next text format message from the specified file.

    Message blocks are separated by a single blank line.

    *f*, a ``file`` or ``str``.  If *f* is text, it is treated as the
    pathname of a file to open.

    *idna_codec*, a ``dns.name.IDNACodec``, specifies the IDNA
    encoder/decoder.  If ``None``, the default IDNA 2003 encoder/decoder
    is used.

    *one_rr_per_rrset*, a ``bool``.  If ``True``, then each RR is put
    into its own rrset.  The default is ``False``.

    Raises ``dns.message.UnknownHeaderField`` if a header is unknown.

    Raises ``dns.exception.SyntaxError`` if the text is badly formed.

    Returns a ``dns.message.Message object``
    """

    with contextlib.ExitStack() as stack:
        if isinstance(f, str):
            f = stack.enter_context(open(f))
        return from_text(f, idna_codec, one_rr_per_rrset)


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

    Returns a ``dns.message.QueryMessage``
    """

    if isinstance(qname, str):
        qname = dns.name.from_text(qname, idna_codec=idna_codec)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    rdclass = dns.rdataclass.RdataClass.make(rdclass)
    m = QueryMessage()
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

    Returns a ``dns.message.Message`` object whose specific class is
    appropriate for the query.  For example, if query is a
    ``dns.update.UpdateMessage``, response will be too.
    """

    if query.flags & dns.flags.QR:
        raise dns.exception.FormError('specified query message is not a query')
    factory = _message_factory_from_opcode(query.opcode)
    response = factory(id=query.id)
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
