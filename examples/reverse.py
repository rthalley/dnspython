#!/usr/bin/env python3

# Usage: reverse.py <zone_filename>...
#
# This demo script will load in all of the zones specified by the
# filenames on the command line, find all the A RRs in them, and
# construct a reverse mapping table that maps each IP address used to
# the list of names mapping to that address.  The table is then sorted
# nicely and printed.
#
# Note!  The zone name is taken from the basename of the filename, so
# you must use filenames like "/wherever/you/like/dnspython.org" and
# not something like "/wherever/you/like/foo.db" (unless you're
# working with the ".db" GTLD, of course :)).
#
# If this weren't a demo script, there'd be a way of specifying the
# origin for each zone instead of constructing it from the filename.

import dns.zone
import dns.ipv4
import os.path
import sys
from typing import Dict, List  # pylint: disable=unused-import

reverse_map = {}  # type: Dict[str, List[str]]

for filename in sys.argv[1:]:
    zone = dns.zone.from_file(filename, os.path.basename(filename), relativize=False)
    for (name, ttl, rdata) in zone.iterate_rdatas("A"):
        print(type(rdata))
        try:
            reverse_map[rdata.address].append(name.to_text())
        except KeyError:
            reverse_map[rdata.address] = [name.to_text()]

for k in sorted(reverse_map.keys(), key=dns.ipv4.inet_aton):
    v = reverse_map[k]
    v.sort()
    print(k, v)
