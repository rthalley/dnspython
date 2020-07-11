import unittest

import dns.rdtypes.IN.A
import dns.message
import dns.rdatatype
import dns.json
import dns.rdataclass
import dns.name

from tests.test_zone import here

class JsonEncodeTestCase(unittest.TestCase):

    def test_zone_encode(self):
        z = dns.zone.from_file(here('example'), 'example')
        s = dns.json.dumps(z, indent=4)
        print(s)

    def test_message_encode(self):
        msg = dns.message.make_query('example.com.', rdtype=dns.rdatatype.A)
        msg.find_rrset(msg.question, dns.name.from_text('example.com.'),
                                create=True, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN)
        rrset = msg.find_rrset(msg.answer, dns.name.from_text('example.com.'),
                                create=True, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, '1.2.3.4'), ttl=1234)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, '1.2.3.5'))
        s = dns.json.dumps(msg, indent=4)
        print(s)

    def test_rrset_encode(self):
        a_rrset = dns.rrset.from_text('foo', 300, 'in', 'a', '10.0.0.1', '10.0.0.2')
        s = dns.json.dumps(a_rrset, indent=4)
        print(s)

        aaaa_rrset = dns.rrset.from_text('foo', 300, 'in', 'aaaa', '::', '1::')
        s = dns.json.dumps(aaaa_rrset, indent=4)
        print(s)

        txt_rrset = dns.rrset.from_text('foo', 300, 'any', 'txt', '"v=spf1 -all"', '1::')
        s = dns.json.dumps(txt_rrset, indent=4)
        print(s)

        dnskey_rrset = dns.rrset.from_text('foo', 300, 'any', 'dnskey',
                                           '257 3 5 AwEAAenVTr9L1OMlL1/N2ta0Qj9LLLnnmFWIr1dJoAsWM9BQfsbV7kFZ '
                                           'XbAkER/FY9Ji2o7cELxBwAsVBuWn6IUUAJXLH74YbC1anY0lifjgt29z '
                                           'SwDzuB7zmC7yVYZzUunBulVW4zT0tg1aePbpVL2EtTL8VzREqbJbE25R '
                                           'KuQYHZtFwG8S4iBxJUmT2Bbd0921LLxSQgVoFXlQx/gFV2+UERXcJ5ce '
                                           'iX6A6wc02M/pdg/YbJd2rBa0MYL3/Fz/Xltre0tqsImZGxzi6YtYDs45 '
                                           'NC8gH+44egz82e2DATCVM1ICPmRDjXYTLldQiWA2ZXIWnK0iitl5ue24 7EsWJefrIhE=')
        s = dns.json.dumps(dnskey_rrset, indent=4)
        print(s)

    def test_rdataset_encode(self):
        r1 = dns.rrset.from_text('foo', 300, 'in', 'a', '10.0.0.1', '10.0.0.2')
        rdataset = r1.to_rdataset()
        s = dns.json.dumps(rdataset, indent=4)
        print(s)

    def test_rdata_encode(self):
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "1.2.3.4")
        s = dns.json.dumps(rdata, indent=4)
        print(s)

    def test_name_encode(self):
        name = dns.name.from_text('example.com')
        s = dns.json.dumps(name, indent=4)
        print(s)

class JsonDecodeTestCase(unittest.TestCase):

    def test_dns_message_decode(self):
        text = """\
{
  "Status": 0,
  "ID": 12345,
  "TC": false,
  "RD": true,
  "RA": true,
  "AD": true,
  "CD": false,
  "Question": [
    {
      "name": "example.com",
      "type": 48
    }
  ],
  "Answer": [
    {
      "name": "example.com",
      "type": 48,
      "TTL": 1446,
      "data": "256 3 RSASHA256 AwEAAdTxhSwz3/lGdlPuQdw+WzsBPmt99VBxvkpfbST65UlCgWOW+5fnGbxfFSrscnQixl6ApgVBYE1Z9KuBRf5y9OD69arf3EYLoE3tYvFreCbcl7sFfWhhZUkBLE028i4pzFhdStQO+yY8xzE3zg1NE86wQUT0LChhMudSpXAmf6DJ"
    },
    {
      "name": "example.com",
      "type": 48,
      "TTL": 1446,
      "data": "257 3 RSASHA256 AwEAAZ0aqu1rJ6orJynrRfNpPmayJZoAx9Ic2/Rl9VQWLMHyjxxem3VUSoNUIFXERQbj0A9Ogp0zDM9YIccKLRd6LmWiDCt7UJQxVdD+heb5Ec4qlqGmyX9MDabkvX2NvMwsUecbYBq8oXeTT9LRmCUt9KUt/WOi6DKECxoG/bWTykrXyBR8elD+SQY43OAVjlWrVltHxgp4/rhBCvRbmdflunaPIgu27eE2U4myDSLT8a4A0rB5uHG4PkOa9dIRs9y00M2mWf4lyPee7vi5few2dbayHXmieGcaAHrx76NGAABeY393xjlmDNcUkF1gpNWUla4fWZbbaYQzA93mLdrng+M="
    },
    {
      "name": "example.com",
      "type": 48,
      "TTL": 1446,
      "data": "257 3 RSASHA256 AwEAAbOFAxl+Lkt0UMglZizKEC1AxUu8zlj65KYatR5wBWMrh18TYzK/ig6Y1t5YTWCO68bynorpNu9fqNFALX7bVl9/gybA0v0EhF+dgXmoUfRX7ksMGgBvtfa2/Y9a3klXNLqkTszIQ4PEMVCjtryl19Be9/PkFeC9ITjgMRQsQhmB39eyMYnal+f3bUxKk4fq7cuEU0dbRpue4H/N6jPucXWOwiMAkTJhghqgy+o9FfIp+tR/emKao94/wpVXDcPf5B18j7xz2SvTTxiuqCzCMtsxnikZHcoh1j4g+Y1B8zIMIvrEM+pZGhh/Yuf4RwCBgaYCi9hpiMWVvS4WBzx0/lU="
    }
  ]
}"""
        msg = dns.json.loads(text)
        print(msg)
        text2 = dns.json.dumps(msg, indent=4)
        print(text2)
        msg2 = dns.json.loads(text2)
        print(msg2)
        text3 = dns.json.dumps(msg2, indent=4)
        print(text3)


if __name__ == '__main__':
    unittest.main()
