# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import dns.name
import dns.wirebase


class Parser(dns.wirebase.Parser):

    def get_name(
        self, origin: dns.name.Name | None = None, decompress: bool = False
    ) -> dns.name.Name:
        name = dns.name.from_wire_parser(self, decompress)
        if origin:
            name = name.relativize(origin)
        return name
