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

"""trio async I/O library DNS stub resolver."""

import random
import socket
import trio
from urllib.parse import urlparse

import dns.exception
import dns.query
import dns.resolver
import dns.trio.query

# import resolver symbols for compatibility and brevity
from dns.resolver import NXDOMAIN, YXDOMAIN, NoAnswer, NoNameservers, \
    NotAbsolute, NoRootSOA, NoMetaqueries, Answer

# we do this for indentation reasons below
_udp = dns.trio.query.udp
_stream = dns.trio.query.stream

class Resolver(dns.resolver.Resolver):

    async def resolve(self, qname, rdtype=dns.rdatatype.A,
                      rdclass=dns.rdataclass.IN,
                      tcp=False, source=None, raise_on_no_answer=True,
                      source_port=0, search=None):
        """Query nameservers asynchronously to find the answer to the question.

        The *qname*, *rdtype*, and *rdclass* parameters may be objects
        of the appropriate type, or strings that can be converted into objects
        of the appropriate type.

        *qname*, a ``dns.name.Name`` or ``str``, the query name.

        *rdtype*, an ``int`` or ``str``,  the query type.

        *rdclass*, an ``int`` or ``str``,  the query class.

        *tcp*, a ``bool``.  If ``True``, use TCP to make the query.

        *source*, a ``str`` or ``None``.  If not ``None``, bind to this IP
        address when making queries.

        *raise_on_no_answer*, a ``bool``.  If ``True``, raise
        ``dns.resolver.NoAnswer`` if there's no answer to the question.

        *source_port*, an ``int``, the port from which to send the message.

        *search*, a ``bool`` or ``None``, determines whether the search
        list configured in the system's resolver configuration are
        used.  The default is ``None``, which causes the value of
        the resolver's ``use_search_by_default`` attribute to be used.

        Raises ``dns.resolver.NXDOMAIN`` if the query name does not exist.

        Raises ``dns.resolver.YXDOMAIN`` if the query name is too long after
        DNAME substitution.

        Raises ``dns.resolver.NoAnswer`` if *raise_on_no_answer* is
        ``True`` and the query name exists but has no RRset of the
        desired type and class.

        Raises ``dns.resolver.NoNameservers`` if no non-broken
        nameservers are available to answer the question.

        Returns a ``dns.resolver.Answer`` instance.

        """

        if isinstance(qname, str):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            raise NoMetaqueries
        if isinstance(rdclass, str):
            rdclass = dns.rdataclass.from_text(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            raise NoMetaqueries
        qnames_to_try = self._get_qnames_to_try(qname, search)
        all_nxdomain = True
        nxdomain_responses = {}
        _qname = None  # make pylint happy
        for _qname in qnames_to_try:
            if self.cache:
                answer = self.cache.get((_qname, rdtype, rdclass))
                if answer is not None:
                    if answer.rrset is None and raise_on_no_answer:
                        raise NoAnswer(response=answer.response)
                    else:
                        return answer
            request = dns.message.make_query(_qname, rdtype, rdclass)
            if self.keyname is not None:
                request.use_tsig(self.keyring, self.keyname,
                                 algorithm=self.keyalgorithm)
            request.use_edns(self.edns, self.ednsflags, self.payload)
            if self.flags is not None:
                request.flags = self.flags
            response = None
            #
            # make a copy of the servers list so we can alter it later.
            #
            nameservers = self.nameservers[:]
            errors = []
            if self.rotate:
                random.shuffle(nameservers)
            backoff = 0.10
            # keep track of nameserver and port
            # to include them in Answer
            nameserver_answered = None
            port_answered = None
            while response is None:
                if len(nameservers) == 0:
                    raise NoNameservers(request=request, errors=errors)
                for nameserver in nameservers[:]:
                    port = self.nameserver_ports.get(nameserver, self.port)
                    protocol = urlparse(nameserver).scheme
                    try:
                        with trio.fail_after(self.timeout):
                            if protocol == 'https':
                                raise NotImplementedError
                            elif protocol:
                                continue
                            tcp_attempt = tcp
                            if tcp:
                                response = await \
                                    _stream(request, nameserver,
                                            port=port,
                                            source=source,
                                            source_port=source_port)
                            else:
                                try:
                                    response = await \
                                        _udp(request,
                                             nameserver,
                                             port=port,
                                             source=source,
                                             source_port=source_port)
                                except dns.message.Truncated:
                                    # Response truncated; retry with TCP.
                                    tcp_attempt = True
                                    response = await \
                                        _stream(request, nameserver,
                                                port=port,
                                                source=source,
                                                source_port=source_port)
                    except (socket.error, trio.TooSlowError) as ex:
                        #
                        # Communication failure or timeout.  Go to the
                        # next server
                        #
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    except dns.query.UnexpectedSource as ex:
                        #
                        # Who knows?  Keep going.
                        #
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    except dns.exception.FormError as ex:
                        #
                        # We don't understand what this server is
                        # saying.  Take it out of the mix and
                        # continue.
                        #
                        nameservers.remove(nameserver)
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    except EOFError as ex:
                        #
                        # We're using TCP and they hung up on us.
                        # Probably they don't support TCP (though
                        # they're supposed to!).  Take it out of the
                        # mix and continue.
                        #
                        nameservers.remove(nameserver)
                        errors.append((nameserver, tcp_attempt, port, ex,
                                       response))
                        response = None
                        continue
                    nameserver_answered = nameserver
                    port_answered = port
                    rcode = response.rcode()
                    if rcode == dns.rcode.YXDOMAIN:
                        yex = YXDOMAIN()
                        errors.append((nameserver, tcp_attempt, port, yex,
                                       response))
                        raise yex
                    if rcode == dns.rcode.NOERROR or \
                       rcode == dns.rcode.NXDOMAIN:
                        break
                    #
                    # We got a response, but we're not happy with the
                    # rcode in it.  Remove the server from the mix if
                    # the rcode isn't SERVFAIL.
                    #
                    if rcode != dns.rcode.SERVFAIL or not self.retry_servfail:
                        nameservers.remove(nameserver)
                    errors.append((nameserver, tcp_attempt, port,
                                   dns.rcode.to_text(rcode), response))
                    response = None
                if response is not None:
                    break
                #
                # All nameservers failed!
                #
                if len(nameservers) > 0:
                    #
                    # But we still have servers to try.  Sleep a bit
                    # so we don't pound them!
                    #
                    await trio.sleep(backoff)
                    backoff *= 2
                    if backoff > 2:
                        backoff = 2
            if response.rcode() == dns.rcode.NXDOMAIN:
                nxdomain_responses[_qname] = response
                continue
            all_nxdomain = False
            break
        if all_nxdomain:
            raise NXDOMAIN(qnames=qnames_to_try, responses=nxdomain_responses)
        answer = Answer(_qname, rdtype, rdclass, response, raise_on_no_answer,
                        nameserver_answered, port_answered)
        if self.cache:
            self.cache.put((_qname, rdtype, rdclass), answer)
        return answer

    async def query(self, *args, **kwargs):
        # We have to define something here as we don't want to inherit the
        # parent's query().
        raise NotImplementedError

    async def resolve_address(self, ipaddr, *args, **kwargs):
        """Use an asynchronous resolver to run a reverse query for PTR
        records.

        This utilizes the resolve() method to perform a PTR lookup on the
        specified IP address.

        *ipaddr*, a ``str``, the IPv4 or IPv6 address you want to get
        the PTR record for.

        All other arguments that can be passed to the resolve() function
        except for rdtype and rdclass are also supported by this
        function.

        """

        return await self.resolve(dns.reversename.from_address(ipaddr),
                                  rdtype=dns.rdatatype.PTR,
                                  rdclass=dns.rdataclass.IN,
                                  *args, **kwargs)

default_resolver = None


def get_default_resolver():
    """Get the default asynchronous resolver, initializing it if necessary."""
    if default_resolver is None:
        reset_default_resolver()
    return default_resolver


def reset_default_resolver():
    """Re-initialize default asynchronous resolver.

    Note that the resolver configuration (i.e. /etc/resolv.conf on UNIX
    systems) will be re-read immediately.
    """

    global default_resolver
    default_resolver = Resolver()


async def resolve(qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
                  tcp=False, source=None, raise_on_no_answer=True,
                  source_port=0, search=None):
    """Query nameservers asynchronously to find the answer to the question.

    This is a convenience function that uses the default resolver
    object to make the query.

    See ``dns.trio.resolver.Resolver.resolve`` for more information on the
    parameters.
    """

    return await get_default_resolver().resolve(qname, rdtype, rdclass, tcp,
                                                source, raise_on_no_answer,
                                                source_port, search)


async def zone_for_name(name, rdclass=dns.rdataclass.IN, tcp=False,
                        resolver=None):
    """Find the name of the zone which contains the specified name.

    *name*, an absolute ``dns.name.Name`` or ``str``, the query name.

    *rdclass*, an ``int``, the query class.

    *tcp*, a ``bool``.  If ``True``, use TCP to make the query.

    *resolver*, a ``dns.trio.resolver.Resolver`` or ``None``, the
    resolver to use.  If ``None``, the default resolver is used.

    Raises ``dns.resolver.NoRootSOA`` if there is no SOA RR at the DNS
    root.  (This is only likely to happen if you're using non-default
    root servers in your network and they are misconfigured.)

    Returns a ``dns.name.Name``.
    """

    if isinstance(name, str):
        name = dns.name.from_text(name, dns.name.root)
    if resolver is None:
        resolver = get_default_resolver()
    if not name.is_absolute():
        raise NotAbsolute(name)
    while True:
        try:
            answer = await resolver.resolve(name, dns.rdatatype.SOA, rdclass,
                                            tcp)
            if answer.rrset.name == name:
                return name
            # otherwise we were CNAMEd or DNAMEd and need to look higher
        except (NXDOMAIN, NoAnswer):
            pass
        try:
            name = name.parent()
        except dns.name.NoParent:
            raise NoRootSOA
