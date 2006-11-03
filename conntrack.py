#!/usr/bin/env python
"""
Copyright(C) 2006 INL
Written by Victor Stinner <victor.stinner AT inl.fr>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
---
conntrack.py is a clone of conntrack program (written in C)
"""
from pynetfilter_conntrack import NetfilterConntrack, CONNTRACK, \
    L3PROTONUM_REVERSE_NAMES, IPPROTO_REVERSE_NAMES
from optparse import OptionGroup, OptionParser
from IPy import IP
import sys

def parseOptions():
    parser = OptionParser(usage="%prog [options] list|xml|delete")

    common = OptionGroup(parser, "Options")
    common.add_option("--quiet", help="Be quiet",
        action="store_true", default=False)
    parser.add_option_group(common)

    common = OptionGroup(parser, "Filter")

    # Filter on IP
    common.add_option("-s", "--orig-src", help="Source address from original direction",
        action="store", type="string", default=None)
    common.add_option("-d", "--orig-dst", help="Destination address from original direction",
        action="store", type="string", default=None)
    common.add_option("-r", "--reply-src", help="Source address from reply direction",
        action="store", type="string", default=None)
    common.add_option("-q", "--reply-dst", help="Destination address from reply direction",
        action="store", type="string", default=None)


    # Filter on port
    common.add_option("--orig-src-port", "--sport", help="Source port from original direction",
        action="store", type="int", default=None)
    common.add_option("--orig-dst-port", "--dport", help="Destination port from original direction",
        action="store", type="int", default=None)
    common.add_option("--reply-src-port", help="Source port from reply direction",
        action="store", type="int", default=None)
    common.add_option("--reply-dst-port", help="Destination port from reply direction",
        action="store", type="int", default=None)
    common.add_option("-p", "--protonum", help="Layer 4 Protocol, eg. 'udp' (default: tcp)",
        action="store", type="string", default="tcp")
    common.add_option("-f", "--family", help="Layer 3 Protocol, eg. 'ipv6' (default: ipv4)",
        action="store", type="string", default="ipv4")
    parser.add_option_group(common)

    # Parse options
    values, arguments = parser.parse_args()

    # Check option values
    if values.orig_src:
        values.orig_src = IP(values.orig_src)
    if values.orig_dst:
        values.orig_dst = IP(values.orig_dst)
    if values.reply_src:
        values.reply_src = IP(values.reply_src)
    if values.reply_dst:
        values.reply_dst = IP(values.reply_dst)
    if values.protonum:
        if values.protonum not in IPPROTO_REVERSE_NAMES:
            print "Unknow protocol number: %s" % values.protonum
            sys.exit(1)
        else:
            values.protonum = IPPROTO_REVERSE_NAMES[values.protonum]
    if values.family not in L3PROTONUM_REVERSE_NAMES:
        print "Unknow layer 3 protocol: %s" % values.family
        sys.exit(1)
    else:
        values.family = L3PROTONUM_REVERSE_NAMES[values.family]
    if len(arguments) != 1 or arguments[0] not in ("list", "xml", "delete"):
        parser.print_help()
        sys.exit(1)
    return values, arguments[0]

def main():
    values, command = parseOptions()
    verbose = not(values.quiet)

    nf = NetfilterConntrack(CONNTRACK)
    table = nf.create_table(values.family)
    table = table.filter(values.protonum,
        orig_src=values.orig_src,
        orig_dst=values.orig_dst,
        orig_src_port=values.orig_src_port,
        orig_dst_port=values.orig_dst_port,
        reply_src=values.reply_src,
        reply_dst=values.reply_dst,
        reply_src_port=values.reply_src_port,
        reply_dst_port=values.reply_dst_port)
    if command == "delete":
        for entry in table:
            if verbose:
                print "Delete: %s (id %s)" % (entry, entry.id)
            nf.delete_conntrack(entry)
    elif command == "xml":
        table.export_xml(sys.stdout)
    else: # list
        table.display()

if __name__ == "__main__":
    main()

