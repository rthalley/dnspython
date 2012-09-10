#!/usr/bin/env python
#
# library and commandline tool to graph DNS resolution paths, especially useful
# for finding errors and inconsistencies
#
# ./tracegraph -h gives you help output
#
# Requires dnspython to do all the heavy lifting
#
# (c)2012 Dennis Kaarsemaker <dennis@kaarsemaker.net>
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import dns.resolver
import sys

__dot_formats = (
    'bmp', 'canon', 'dot', 'xdot', 'cmap', 'eps', 'fig', 'gd', 'gd2', 'gif',
    'gtk', 'ico', 'imap', 'cmapx', 'imap_np', 'cmapx_np', 'ismap', 'jpg',
    'jpeg', 'jpe', 'pdf', 'plain', 'plain-ext', 'png', 'ps', 'ps2', 'svg',
    'svgz', 'tif', 'tiff', 'vml', 'vmlz', 'vrml', 'wbmp', 'webp', 'xlib'
)

log = lambda x: sys.stderr.write(x + "\n")

class Zone(object):
    def __init__(self, name, parent=None):
        self.name = name
        self.resolvers = {}
        self.root = parent or self

        if name == '.':
            self.subzones = {}
            self.names = {}

    def trace(self, name, rdtype=dns.rdatatype.A):
        if self.name == '.' and not self.resolvers:
            self.find_root_resolvers()
        if not name.endswith('.'):
            name += '.'
        for resolver in sorted(self.resolvers.values(), key=lambda x: x.name):
            resolver.resolve(name, rdtype=rdtype)

    def resolve(self, name, rdtype=dns.rdatatype.A):
        if self.name == '.' and not self.resolvers:
            self.find_root_resolvers()
        if name in self.root.names:
            return self.root.names[name].ip
        return self.resolvers.values()[0].resolve(name, rdtype=rdtype, register=False)

    def find_root_resolvers(self):
        for root in 'abcdefghijklm':
            root += '.root-servers.net.'
            self.resolvers[root] = Resolver(self, root)
            self.resolvers[root].ip = [x.address for x in dns.resolver.query(root,rdtype=dns.rdatatype.A).response.answer[0]]
            self.resolvers[root].up = []

    def graph(self, skip=[], errors_only=False):
        graph = ["digraph dns {", "    rankdir=LR;", "    subgraph {", "        rank=same;"]

        # Add all final resolution results
        for name in sorted(self.names):
            for address in self.names[name].addresses:
                if address in ('NXDOMAIN','SERVFAIL'):
                    graph.append('        "%s" [shape="box",color="red",fontcolor="red"];' % address)
                elif not errors_only:
                    graph.append('        "%s" [shape="doubleoctagon"];' % address)
        graph.append("    }")

        # Final hops
        for name in sorted(self.names):
            all_ns = set()
            for address in self.names[name].addresses:
                all_ns.update(self.names[name].addresses[address])
            for address in self.names[name].addresses:
                for ns in self.names[name].addresses[address]:
                    if ns.zone.name in skip:
                        continue
                    if address in ('NXDOMAIN','SERVFAIL'):
                        graph.append('    "%s" -> "%s" [label="%s",color="red",fontcolor="red"];' % (ns.name, address, name))
                    elif not errors_only:
                        graph.append('    "%s" -> "%s" [label="%s"];' % (ns.name, address, name))
                # Missing links
                if address in ('NXDOMAIN','SERVFAIL'):
                    continue
                for ns in all_ns:
                    if ns.zone.name in skip:
                        continue
                    if ns in self.names[name].addresses[address]:
                        continue
                    graph.append('    "%s" -> "%s" [label="%s",color="red",fontcolor="red"];' % (ns.name, address, name))

        # And hop all zones back
        for zone in sorted(self.subzones.values() + [self], key=lambda x: x.name):
            if zone.name in skip:
                continue
            all_upns = set()
            for ns in zone.resolvers:
                all_upns.update(zone.resolvers[ns].up)
            for ns in zone.resolvers:
                if not errors_only:
                    for upns in zone.resolvers[ns].up:
                        if upns.zone.name in skip:
                            continue
                        graph.append('    "%s" -> "%s" [label="%s"];' % (upns.name, ns, zone.name))
                # Missing links
                for upns in all_upns:
                    if upns.zone.name in skip:
                        continue
                    if upns in zone.resolvers[ns].up:
                        continue
                    graph.append('    "%s" -> "%s" [label="%s",color="red",fontcolor="red"];' % (upns.name, ns, zone.name))

        graph.append('}')
        return graph
    
    def dump(self, format, fd):
        if format == 'yaml':
            import yaml
            return yaml.dump(self.serialize(), fd)
        if format == 'json':
            import json
            return json.dump(self.serialize(), fd)

    @classmethod
    def load(klass, format, fd):
        if format == 'yaml':
            import yaml
            return klass.deserialize(yaml.load(fd))
        if format == 'json':
            import json
            return klass.deserialize(json.load(fd))

    def dumps(self, format):
        pass

    def loads(self, format):
        pass
    
    def serialize(self):
        ret = {
            'name': self.name,
            'resolvers': [x.serialize() for x in self.resolvers.values()],
            'zones': [],
            'names': [],
        }
        if self.name == '.':
            done = ['.']
            # Order them in such a way that we don't need to jump through hoops when deserializing 
            def add_zone(zone):
                if zone.name in done:
                    return
                for resolver in zone.resolvers.values():
                    for up in resolver.up:
                        if up.zone.name not in done:
                            add_zone(up.zone)
                ret['zones'].append(zone.serialize())
                done.append(zone.name)

            for zone in self.subzones.values():
                add_zone(zone)
            for name in self.names.values():
                ret['names'].append(name.serialize())
        return ret

    @classmethod
    def deserialize(klass, data, root=None):
        inst = klass(data['name'], root)
        for resolver in data['resolvers']:
            resolver = Resolver.deserialize(resolver, inst)
            inst.resolvers[resolver.name] = resolver
        if root:
            root.subzones[inst.name] = inst
        if not root:
            inst.subzones['.'] = inst
            for zone in data['zones']:
                Zone.deserialize(zone, inst)
            inst.subzones.pop('.')
            for name in data['names']:
                name = Name.deserialize(name, inst)
                inst.names[name.name] = name
        return inst
    
class Name(object):
    def __init__(self, name):
        self.name = name
        self.addresses = {}

    def serialize(self):
        return {
            'name': self.name,
            'addresses': dict([(addr, [(res.zone.name, res.name) for res in self.addresses[addr]]) for addr in self.addresses])
        }

    @classmethod
    def deserialize(klass, data, root):
        inst = klass(data['name'])
        for addr in data['addresses']:
            inst.addresses[addr] = []
            for zone,resolver in data['addresses'][addr]:
                inst.addresses[addr].append(root.subzones[zone].resolvers[resolver])
        return inst

class Resolver(object):
    def __init__(self, zone, name):
        self.zone = zone
        self.name = name
        self.root = self.zone.root
        self.ip = []
        self.up = []

    def resolve(self, name, rdtype=dns.rdatatype.A, register=True):
        if not self.ip:
            self.ip = self.root.resolve(self.name)
        res = dns.resolver.Resolver(configure=False)
        res.nameservers = self.ip
        log("Trying to resolve %s on %s (%s)" % (name, self.name, self.ip[0]))
        try:
            ans = res.query(name, rdtype=rdtype, raise_on_no_answer=False)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            # Insert a bogus name node for NXDOMAIN/SERVFAIL
            msg = {dns.resolver.NXDOMAIN: 'NXDOMAIN', dns.resolver.NoNameservers: 'SERVFAIL'}[sys.exc_type]
            if not register:
                raise
            if name not in self.root.names:
                self.root.names[name] = Name(name)
            name = self.root.names[name]
            if msg not in name.addresses:
                name.addresses[msg] = []
            name.addresses[msg].append(self)
            return

        if not ans.response.answer:
            # OK, we're being sent a level lower
            zone = None
            for record in ans.response.authority:
                zone = record.name.to_text()
                if record.rdtype == dns.rdatatype.NS:
                    if not register:
                        zone = Zone(zone, self.root)
                    else:
                        if zone not in self.root.subzones:
                            self.root.subzones[zone] = Zone(zone, self.root)
                        zone = self.root.subzones[zone]

                    for item in record.items:
                        ns = item.target.to_text()
                        if ns not in zone.resolvers:
                            zone.resolvers[ns] = Resolver(zone, ns)
                        if self not in zone.resolvers[ns].up:
                            zone.resolvers[ns].up.append(self)

            # Process glue records
            for record in ans.response.additional:
                if record.rdtype == dns.rdatatype.A:
                    zone.resolvers[record.name.to_text()].ip = [x.address for x in record.items]

            # Simple resolution?
            if not register:
                return zone.resolve(name, rdtype)
            # We're doing a depth-first search, so by now the name may actually be resolved already
            if name not in self.root.names:
                return zone.trace(name, rdtype)
        
        # Real answer
        names = {}
        resolve = []
        orig_name = name

        for record in ans.response.answer:
            name = record.name.to_text()
            if name not in names:
                if name in self.root.names:
                    names[name] = self.root.names[name]
                else:
                    names[name] = Name(name)
            name = names[name]

            if record.rdtype == dns.rdatatype.A:
                for x in record.items:
                    addr = x.address
                    if addr not in name.addresses:
                        name.addresses[addr] = []
                    name.addresses[addr].append(self)

            elif record.rdtype == dns.rdatatype.MX:
                for x in record.items:
                    addr = x.exchange.to_text()
                    resolve.append(addr)
                    if addr not in name.addresses:
                        name.addresses[addr] = []
                    name.addresses[addr].append(self)

            elif record.rdtype == dns.rdatatype.CNAME:
                for x in record.items:
                    cname = x.target.to_text()
                    resolve.append(cname)
                    if cname not in name.addresses:
                        name.addresses[cname] = []
                    name.addresses[cname].append(self)

            else:
                raise RuntimeError("Unknown record:" + str(record))

        if not register:
            return names[orig_name].addresses.keys()
        
        self.root.names.update(names)
        for name in resolve:
            if name not in self.root.names:
                self.root.trace(name)

    def serialize(self):
        return {
            'name': self.name,
            'ip': self.ip,
            'up': [(res.zone.name, res.name) for res in self.up],
        }

    @classmethod
    def deserialize(klass, data, zone):
        inst = klass(zone, data['name'])
        inst.ip = data['ip']
        for zone, resolver in data['up']:
            inst.up.append(inst.root.subzones[zone].resolvers[resolver])
        return inst

def root():
    return Zone('.')

if __name__ == '__main__':
    import optparse
    import subprocess

    usage = """%prog [options] name - Trace all resolution paths for a name and graph them

Examples:
%prog -t MX --graph png --output booking.png --skip . --skip com. booking.com
%prog --skip . kaarsemaker.net --dump=kaarsemaker.yaml
%prog --load broken_example.yaml --errors-only --graph png --output example.png"""

    p = optparse.OptionParser(usage=usage)
    p.add_option('-q', '--quiet', dest='quiet', action="store_true", default=False,
                 help="No diagnostic messages")
    p.add_option('-t', '--type', dest='rdtype', default='A', choices=('A', 'MX'),
                 help="Which record type to query")
    p.add_option('-d', '--dump', dest='dump', default=None, metavar='FILE',
                 help="Dump resolver data to a file")
    p.add_option('-l', '--load', dest='load', default=None, metavar='FILE',
                 help="Load resolver data from a file")
    p.add_option('-f', '--format', dest='format', default='yaml', choices=('yaml','json'),
                 help="Dump/load format")
    p.add_option('-g', '--graph', dest='graph', default=None, metavar='FORMAT',
                 choices=__dot_formats, help="Graph format, see dot(1)")
    p.add_option('-o', '--output', dest='output', default=None, metavar='FILE',
                 help="Filename for the graph")
    p.add_option('-s', '--skip', dest='skip', action='append', default=[],
                 help="Zone to skip in the graph (may be repeated)")
    p.add_option('-e', '--errors-only', dest="errors_only", action="store_true", default=False,
                 help="Only show error nodes and vertices")
    p.add_option('-n', '--nagios', dest="nagios", action="store_true", default=False,
                 help="Function as a nagios plug-in")

    opts, args = p.parse_args()

    if opts.load:
        if args:
            p.error("You're loading a dump so no extra queries")
            p.exit(1)
    else:
        if len(args) != 1:
            p.error("You must specify exactly one name to graph")
            p.exit(1)

    if not (opts.graph or opts.dump or opts.nagios):
        p.error("At least one of --dump, --graph and --nagios is required")
        p.exit(1)

    if opts.quiet:
        log = lambda x: None

    rdtype = dns.rdatatype.from_text(opts.rdtype)
    skip = [x if x.endswith('.') else x + '.' for x in opts.skip]

    if opts.load:
        with open(opts.load) as fd:
            root = Zone.load(opts.format, fd)
    else:
        name = args[0]
        root = root()
        root.trace(name, rdtype=rdtype)

    if opts.dump:
        with open(opts.dump, 'w') as fd:
            root.dump(opts.format, fd)

    if opts.graph:
        graph = root.graph(skip=skip, errors_only=opts.errors_only)
        cmd = ["dot", "-T", opts.graph]
        if opts.output:
            cmd += ["-o", opts.output]
        sp = subprocess.Popen(cmd, stdin=subprocess.PIPE)
        sp.communicate("\n".join(graph))

    if opts.nagios:
        graph = root.graph(errors_only=True)
        nerrors = len([x for x in graph if '->' in x])
        if nerrors:
            print("%d inconsistenies in the dns graph, run with -e -g png for details" % nerrors)
            sys.exit(2)
        else:
            print("DNS trace graph consistent")
