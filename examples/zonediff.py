#!/usr/bin/env python3
#
# Small library and commandline tool to do logical diffs of zonefiles
# ./zonediff -h gives you help output
#
# Requires dnspython to do all the heavy lifting
#
# (c)2009 Dennis Kaarsemaker <dennis@kaarsemaker.net>
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
"""See diff_zones.__doc__ for more information"""

from typing import Any, Union, cast  # pylint: disable=unused-import

__all__ = ["diff_zones", "format_changes_plain", "format_changes_html"]

try:
    import dns.node
    import dns.zone
except ImportError:
    raise SystemExit("Please install dnspython")


def diff_zones(
    zone1,  # type: dns.zone.Zone
    zone2,  # type: dns.zone.Zone
    ignore_ttl=False,
    ignore_soa=False,
):  # type: (...) -> list
    """diff_zones(zone1, zone2, ignore_ttl=False, ignore_soa=False) -> changes
    Compares two dns.zone.Zone objects and returns a list of all changes
    in the format (name, oldnode, newnode).

    If ignore_ttl is true, a node will not be added to this list if the
    only change is its TTL.

    If ignore_soa is true, a node will not be added to this list if the
    only changes is a change in a SOA Rdata set.

    The returned nodes do include all Rdata sets, including unchanged ones.
    """

    changes = []
    for name in zone1:
        namestr = str(name)
        n1 = cast(dns.node.Node, zone1.get_node(namestr))
        n2 = cast(dns.node.Node, zone2.get_node(namestr))
        if not n2:
            changes.append((str(name), n1, n2))
        elif _nodes_differ(n1, n2, ignore_ttl, ignore_soa):
            changes.append((str(name), n1, n2))

    for name in zone2:
        n3 = cast(dns.node.Node, zone1.get_node(name))
        if not n3:
            n4 = cast(dns.node.Node, zone2.get_node(name))
            changes.append((str(name), n3, n4))
    return changes


def _nodes_differ(
    n1,  # type: dns.node.Node
    n2,  # type: dns.node.Node
    ignore_ttl,  # type: bool
    ignore_soa,  # type: bool
):  # type: (...) -> bool
    if ignore_soa or not ignore_ttl:
        # Compare datasets directly
        for r in n1.rdatasets:
            if ignore_soa and r.rdtype == dns.rdatatype.SOA:
                continue
            if r not in n2.rdatasets:
                return True
            if not ignore_ttl:
                return r.ttl != n2.find_rdataset(r.rdclass, r.rdtype).ttl

        for r in n2.rdatasets:
            if ignore_soa and r.rdtype == dns.rdatatype.SOA:
                continue
            if r not in n1.rdatasets:
                return True
        assert False
    else:
        return n1 != n2


def format_changes_plain(
    oldf,  # type: str
    newf,  # type: str
    changes,  # type: list
    ignore_ttl=False,
):  # type: (...) -> str
    """format_changes(oldfile, newfile, changes, ignore_ttl=False) -> str
    Given 2 filenames and a list of changes from diff_zones, produce diff-like
    output. If ignore_ttl is True, TTL-only changes are not displayed"""

    ret = "--- {}\n+++ {}\n".format(oldf, newf)
    for name, old, new in changes:
        ret += "@ %s\n" % name
        if not old:
            for r in new.rdatasets:
                ret += "+ %s\n" % str(r).replace("\n", "\n+ ")
        elif not new:
            for r in old.rdatasets:
                ret += "- %s\n" % str(r).replace("\n", "\n+ ")
        else:
            for r in old.rdatasets:
                if r not in new.rdatasets or (
                    r.ttl != new.find_rdataset(r.rdclass, r.rdtype).ttl
                    and not ignore_ttl
                ):
                    ret += "- %s\n" % str(r).replace("\n", "\n+ ")
            for r in new.rdatasets:
                if r not in old.rdatasets or (
                    r.ttl != old.find_rdataset(r.rdclass, r.rdtype).ttl
                    and not ignore_ttl
                ):
                    ret += "+ %s\n" % str(r).replace("\n", "\n+ ")
    return ret


def format_changes_html(
    oldf,  # type: str
    newf,  # type: str
    changes,  # type: list
    ignore_ttl=False,
):  # type: (...) -> str
    """format_changes(oldfile, newfile, changes, ignore_ttl=False) -> str
    Given 2 filenames and a list of changes from diff_zones, produce nice html
    output. If ignore_ttl is True, TTL-only changes are not displayed"""

    ret = """<table class="zonediff">
  <thead>
    <tr>
      <th>&nbsp;</th>
      <th class="old">%s</th>
      <th class="new">%s</th>
    </tr>
  </thead>
  <tbody>\n""" % (
        oldf,
        newf,
    )

    for name, old, new in changes:
        ret += '    <tr class="rdata">\n      <td class="rdname">%s</td>\n' % name
        if not old:
            for r in new.rdatasets:
                ret += (
                    '      <td class="old">&nbsp;</td>\n'
                    '      <td class="new">%s</td>\n'
                ) % str(r).replace("\n", "<br />")
        elif not new:
            for r in old.rdatasets:
                ret += (
                    '      <td class="old">%s</td>\n'
                    '      <td class="new">&nbsp;</td>\n'
                ) % str(r).replace("\n", "<br />")
        else:
            ret += '      <td class="old">'
            for r in old.rdatasets:
                if r not in new.rdatasets or (
                    r.ttl != new.find_rdataset(r.rdclass, r.rdtype).ttl
                    and not ignore_ttl
                ):
                    ret += str(r).replace("\n", "<br />")
            ret += "</td>\n"
            ret += '      <td class="new">'
            for r in new.rdatasets:
                if r not in old.rdatasets or (
                    r.ttl != old.find_rdataset(r.rdclass, r.rdtype).ttl
                    and not ignore_ttl
                ):
                    ret += str(r).replace("\n", "<br />")
            ret += "</td>\n"
        ret += "    </tr>\n"
    return ret + "  </tbody>\n</table>"


# Make this module usable as a script too.
def main():  # type: () -> None
    import argparse
    import subprocess
    import sys
    import traceback

    usage = """%prog zonefile1 zonefile2 - Show differences between zones in a diff-like format
%prog [--git|--bzr|--rcs] zonefile rev1 [rev2] - Show differences between two revisions of a zonefile

The differences shown will be logical differences, not textual differences.
"""
    p = argparse.ArgumentParser(usage=usage)
    p.add_argument(
        "-s",
        "--ignore-soa",
        action="store_true",
        default=False,
        dest="ignore_soa",
        help="Ignore SOA-only changes to records",
    )
    p.add_argument(
        "-t",
        "--ignore-ttl",
        action="store_true",
        default=False,
        dest="ignore_ttl",
        help="Ignore TTL-only changes to Rdata",
    )
    p.add_argument(
        "-T",
        "--traceback",
        action="store_true",
        default=False,
        dest="tracebacks",
        help="Show python tracebacks when errors occur",
    )
    p.add_argument(
        "-H",
        "--html",
        action="store_true",
        default=False,
        dest="html",
        help="Print HTML output",
    )
    p.add_argument(
        "-g",
        "--git",
        action="store_true",
        default=False,
        dest="use_git",
        help="Use git revisions instead of real files",
    )
    p.add_argument(
        "-b",
        "--bzr",
        action="store_true",
        default=False,
        dest="use_bzr",
        help="Use bzr revisions instead of real files",
    )
    p.add_argument(
        "-r",
        "--rcs",
        action="store_true",
        default=False,
        dest="use_rcs",
        help="Use rcs revisions instead of real files",
    )
    opts, args = p.parse_args()
    opts.use_vc = opts.use_git or opts.use_bzr or opts.use_rcs

    def _open(what, err):  # type: (Union[list,str], str) -> Any
        if isinstance(what, list):
            # Must be a list, open subprocess
            try:
                proc = subprocess.Popen(what, stdout=subprocess.PIPE)
                proc.wait()
                if proc.returncode == 0:
                    return proc.stdout
                sys.stderr.write(err + "\n")
            except Exception:
                sys.stderr.write(err + "\n")
                if opts.tracebacks:
                    traceback.print_exc()
        else:
            # Open as normal file
            try:
                return open(what, "rb")
            except IOError:
                sys.stderr.write(err + "\n")
                if opts.tracebacks:
                    traceback.print_exc()

    if not opts.use_vc and len(args) != 2:
        p.print_help()
        sys.exit(64)
    if opts.use_vc and len(args) not in (2, 3):
        p.print_help()
        sys.exit(64)

    # Open file descriptors
    if not opts.use_vc:
        oldn, newn = args
    else:
        if len(args) == 3:
            filename, oldr, newr = args
            oldn = "{}:{}".format(oldr, filename)
            newn = "{}:{}".format(newr, filename)
        else:
            filename, oldr = args
            newr = None
            oldn = "{}:{}".format(oldr, filename)
            newn = filename

    old, new = None, None
    oldz, newz = None, None
    if opts.use_bzr:
        old = _open(
            ["bzr", "cat", "-r" + oldr, filename],
            "Unable to retrieve revision {} of {}".format(oldr, filename),
        )
        if newr is not None:
            new = _open(
                ["bzr", "cat", "-r" + newr, filename],
                "Unable to retrieve revision {} of {}".format(newr, filename),
            )
    elif opts.use_git:
        old = _open(
            ["git", "show", oldn],
            "Unable to retrieve revision {} of {}".format(oldr, filename),
        )
        if newr is not None:
            new = _open(
                ["git", "show", newn],
                "Unable to retrieve revision {} of {}".format(newr, filename),
            )
    elif opts.use_rcs:
        old = _open(
            ["co", "-q", "-p", "-r" + oldr, filename],
            "Unable to retrieve revision {} of {}".format(oldr, filename),
        )
        if newr is not None:
            new = _open(
                ["co", "-q", "-p", "-r" + newr, filename],
                "Unable to retrieve revision {} of {}".format(newr, filename),
            )
    if not opts.use_vc:
        old = _open(oldn, "Unable to open %s" % oldn)
    if not opts.use_vc or newr is None:
        new = _open(newn, "Unable to open %s" % newn)

    if not old or not new:
        sys.exit(65)

    # Parse the zones
    try:
        oldz = dns.zone.from_file(old, origin=".", check_origin=False)
    except dns.exception.DNSException:
        sys.stderr.write("Incorrect zonefile: %s\n" % old)
        if opts.tracebacks:
            traceback.print_exc()
    try:
        newz = dns.zone.from_file(new, origin=".", check_origin=False)
    except dns.exception.DNSException:
        sys.stderr.write("Incorrect zonefile: %s\n" % new)
        if opts.tracebacks:
            traceback.print_exc()
    if not oldz or not newz:
        sys.exit(65)

    changes = diff_zones(oldz, newz, opts.ignore_ttl, opts.ignore_soa)
    changes.sort()

    if not changes:
        sys.exit(0)
    if opts.html:
        print(format_changes_html(oldn, newn, changes, opts.ignore_ttl))
    else:
        print(format_changes_plain(oldn, newn, changes, opts.ignore_ttl))
    sys.exit(1)


if __name__ == "__main__":
    main()
