import json
from json.decoder import WHITESPACE

import dns.message
import dns.rdataset
import dns.rrset
import dns.zone
import dns.rdata
import dns.rdtypes.IN
import dns.node
import dns.flags
import dns.rdataclass

class DNSJSONEncoder(json.JSONEncoder):
    def default(self, o): # pylint: disable=E0202
        if isinstance(o, dns.zone.Zone):
            return encode_zone(o)
        if isinstance(o, dns.message.Message):
            return encode_message(o)
        if isinstance(o, dns.rrset.RRset):
            return encode_rrset(o)
        if isinstance(o, dns.rdataset.Rdataset):
            return encode_rdataset(o)
        if isinstance(o, dns.name.Name):
            return encode_name(o)
        if isinstance(o, dns.rdata.Rdata):
            return encode_rdata(o)
        return super().default(o)

class DNSJSONDecoder(json.JSONDecoder):
    def decode(self, s, _w=WHITESPACE.match):
        d = json.loads(s)
        if 'Origin' in d:
            return decode_zone(d)
        if 'Status' in d:
            return decode_message(d)
        return d

def dump(o, fp, cls=DNSJSONEncoder, **kwargs):
    return json.dump(o, fp, cls=cls, **kwargs)

def dumps(o, cls=DNSJSONEncoder, **kwargs):
    return json.dumps(o, cls=cls, **kwargs)

def loads(s, cls=DNSJSONDecoder, **kwargs):
    return json.loads(s, cls=cls, **kwargs)

def load(fp, cls=DNSJSONDecoder, **kwargs):
    return json.load(fp, cls=cls, **kwargs)

# Optionally could use these to match dns.message.from_text(), etc
# def to_json(*args, **kwargs):
#     return dumps(*args, **kwargs)
#
# def from_json(*args, **kwargs):
#     return loads(*args, **kwargs)

def decode_message(d):
    msg = dns.message.Message()
    msg.set_rcode(d['Status'])
    if 'ID' in d:
        msg.id = d['ID']
    if 'QR' in d:
        msg.set_opcode(d['QR'])
    if 'TC' in d and d['TC']:
        msg.flags |= dns.flags.TC
    if 'RD' in d and d['RD']:
        msg.flags |= dns.flags.RD
    if 'RA' in d and d['RA']:
        msg.flags |= dns.flags.RA
    if 'AD' in d and d['AD']:
        msg.flags |= dns.flags.AD
    if 'CD' in d and d['CD']:
        msg.flags |= dns.flags.CD
    if 'Question' in d and len(d['Question']) > 0:
        decode_rrsets(msg, msg.question, d['Question'])
    if 'Answer' in d and len(d['Answer']) > 0:
        decode_rrsets(msg, msg.answer, d['Answer'])
    if 'Authority' in d and len(d['Authority']) > 0:
        decode_rrsets(msg, msg.authority, d['Authority'])
    if 'Additional' in d and len(d['Additional']) > 0:
        decode_rrsets(msg, msg.additional, d['Additional'])
    return msg

def decode_rrsets(msg, section, rrsets):
    for i in rrsets:
        rrset = msg.find_rrset(section, dns.name.from_text(i['name']),
                               dns.rdataclass.IN, rdtype=i['type'], create=True)
        if 'data' in i:
            rdata = dns.rdata.from_text(dns.rdataclass.IN, i['type'], i['data'])
            if 'TTL' in i:
                rrset.add(rdata, i['TTL'])
            else:
                rrset.add(rdata)

def decode_zone(d: dict):
    # todo
    return d

def encode_message(message):
    result = {
        'ID': message.id,
        'Status': message.rcode(),
        'QR': message.opcode(),
        'TC': bool(message.flags & dns.flags.TC),
        'RD': bool(message.flags & dns.flags.RD),
        'RA': bool(message.flags & dns.flags.RA),
        'AD': bool(message.flags & dns.flags.AD),
        'CD': bool(message.flags & dns.flags.CD),
        'Question': [],
        'Answer': encode_section(message.answer),
        'Authority': encode_section(message.authority),
        'Additional': encode_section(message.additional),
    }
    if len(message.question) > 0:
        for q in message.question:
            result['Question'].append({
                'name': q.name,
                'type': q.rdtype
            })
    return result

def encode_rrset(rrset, origin=None, relativize=False):
    result = []
    name = rrset.name
    if origin is not None:
        if relativize:
            name = rrset.name.relativize(origin)
        else:
            name = rrset.name.derelativize(origin)
    if len(rrset) == 0:
        result.append({
            'name': name,
            'TTL': rrset.ttl,
            'type': rrset.rdtype,
        })
    for rdata in rrset:
        result.append({
            'name': name,
            'TTL': rrset.ttl,
            'type': rrset.rdtype,
            'data': rdata
        })
    return result

def encode_section(section, origin=None):
    result = []
    for rrset in section:
        result.extend(encode_rrset(rrset, origin=origin))
    return result

def encode_name(name):
    return name.to_text()

def encode_rdata(rdata):
    return rdata.to_text()

def encode_zone(zone, relativize=False):
    result = {
        'Origin': zone.origin,
        'RRSets': []
    }
    for name, rdatasets in zone.nodes.items():
        for rdataset in rdatasets:
            if not relativize:
                name = name.derelativize(zone.origin)
            else:
                name = name.relativize(zone.origin)
            rrset = dns.rrset.from_rdata_list(name=name, ttl=rdataset.ttl, rdatas=rdataset)
            result['rrsets'].extend(encode_rrset(rrset))
    return result

def encode_nodes(nodes, origin=None, relativize=False):
    result = []
    for name, rdatasets in nodes.items():
        for rdataset in rdatasets:
            if origin is not None and not relativize:
                name = name.derelativize(origin)
            if origin is not None and relativize:
                name = name.relativize(origin)
            rrset = dns.rrset.from_rdata_list(name=name, ttl=rdataset.ttl, rdatas=rdataset)
            result.extend(encode_rrset(rrset))
    return result

def encode_rdataset(rdataset, name=None):
    result = {
        'class': rdataset.rdclass,
        'type': rdataset.rdtype,
        'rdatas': []
    }
    if name:
        result['name'] = name
    for rdata in rdataset:
        result['rdatas'].append(rdata)
    return result
