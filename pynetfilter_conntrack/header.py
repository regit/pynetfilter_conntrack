#!/usr/bin/env python
"""
Copyright(C) 2006 INL
Written by Victor Stinner <victor.stinner@inl.fr>

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
pynetfilter_conntrack is a Python binding of libnetfilter_conntrack:
   http://www.netfilter.org/projects/libnetfilter_conntrack/index.html
"""
from ctypes import Union, Structure, \
    POINTER, CFUNCTYPE, cast, \
    c_char_p, c_void_p, c_int, c_uint, \
    sizeof, byref, create_string_buffer, cdll
from pynetfilter_conntrack.ctypes_stdint import uint8_t, uint16_t, uint32_t, uint64_t
from pynetfilter_conntrack.tools import ctypes_copy, reverse_dict
from socket import ntohs, htons, ntohl, AF_INET, AF_INET6
from IPy import IP
from cElementTree import Element, SubElement
import types

# ------------------------------- Constants ------------------------------

NFCT_ANY_ID = 0

# Message type
NFCT_MSG_UNKNOWN = 0
NFCT_MSG_NEW = 1
NFCT_MSG_UPDATE = 2
NFCT_MSG_DESTROY = 3

# Python dictionnary to get name of layer 3 protocol
L3PROTONUM_NAMES = {
    AF_INET: "ipv4",
    AF_INET6: "ipv6",
}
L3PROTONUM_REVERSE_NAMES = reverse_dict(L3PROTONUM_NAMES)

# Netfilter subsystem identifier (libnfnetlink/linux_nfnetlink.h)
NFNL_SUBSYS_CTNETLINK = 1
NFNL_SUBSYS_CTNETLINK_EXP = 2
CONNTRACK = NFNL_SUBSYS_CTNETLINK
EXPECT = NFNL_SUBSYS_CTNETLINK_EXP

# Netfilter subscriptions
NF_NETLINK_CONNTRACK_NEW         = 0x00000001
NF_NETLINK_CONNTRACK_UPDATE      = 0x00000002
NF_NETLINK_CONNTRACK_DESTROY     = 0x00000004
NFCT_ALL_CT_GROUPS = NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE | NF_NETLINK_CONNTRACK_DESTROY

# Constants used in structures
NFCT_DIR_ORIGINAL = 0
NFCT_DIR_REPLY = 1
NFCT_DIR_MAX = NFCT_DIR_REPLY+1

# IP protocol numbers (/usr/include/netinet/in.h)
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_SCTP = 132

# Python dictinnoary to convert IP protocol to string
IPPROTO_NAMES = {
    IPPROTO_ICMP: "icmp",
    IPPROTO_TCP: "tcp",
    IPPROTO_UDP: "udp",
    IPPROTO_SCTP: "sctp",
}
IPPROTO_REVERSE_NAMES = reverse_dict(IPPROTO_NAMES)

#---- ip_conntrack_status ---------------

# It's an expected connection: bit 0 set.  This bit never changed
IPS_EXPECTED = (1 << 0)

# We've seen packets both ways: bit 1 set.  Can be set, not unset.
IPS_SEEN_REPLY = (1 << 1)

# Conntrack should never be early-expired.
IPS_ASSURED = (1 << 2)

# Connection is confirmed: originating packet has left box
IPS_CONFIRMED = (1 << 3)

# Connection needs src nat in orig dir.  This bit never changed.
IPS_SRC_NAT = (1 << 4)

# Connection needs dst nat in orig dir.  This bit never changed.
IPS_DST_NAT = (1 << 5)

# Both together.
IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT)

# Connection needs TCP sequence adjusted.
IPS_SEQ_ADJUST = (1 << 6)

# NAT initialization bits.
IPS_SRC_NAT_DONE = (1 << 7)
IPS_DST_NAT_DONE = (1 << 8)

# Both together
IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE)

# Connection is dying (removed from lists), can not be unset.
IPS_DYING = (1 << 9)

# Connection has fixed timeout.
IPS_FIXED_TIMEOUT = (1 << 10)

# Python tuples to convert status to string
IPS_NAMES = (
    (IPS_EXPECTED, "expected"),
    (IPS_SEEN_REPLY, "seen reply"),
    (IPS_ASSURED, "assured"),
    (IPS_CONFIRMED, "confirmed"),
    (IPS_SRC_NAT, "src_nat"),
    (IPS_DST_NAT, "dst_nat"),
    (IPS_NAT_MASK, "nat_mask"),
    (IPS_SEQ_ADJUST, "seq_adjust"),
    (IPS_SRC_NAT_DONE, "src_nat_done"),
    (IPS_DST_NAT_DONE, "dst_nat_done"),
    (IPS_DYING, "dying"),
    (IPS_FIXED_TIMEOUT, "fixed_timeout"),
)

# --- Netfilter conntrack flags --
NFCT_STATUS = (1 << 0)
NFCT_PROTOINFO = (1 << 1)
NFCT_TIMEOUT = (1 << 2)
NFCT_MARK = (1 << 3)
NFCT_COUNTERS_ORIG = (1 << 4)
NFCT_COUNTERS_RPLY = (1 << 5)
NFCT_USE = (1 << 6)
NFCT_ID = (1 << 7)

# Python dictionnary
NFCT_NAMES = {
    NFCT_STATUS: "status",
    NFCT_PROTOINFO: "protoinfo",
    NFCT_TIMEOUT: "timeout",
    NFCT_MARK: "mark",
    NFCT_COUNTERS_ORIG: "counters orig",
    NFCT_COUNTERS_RPLY: "counters reply",
    NFCT_USE: "use",
    NFCT_ID: "id",
}

# ------------------------------- Types ----------------------------------

nfct_handle_p = c_void_p

class _port_struct(Structure):
    _fields_ = (("port", uint16_t),)

class _icmp_struct(Structure):
    _fields_ = (
        ("type", uint8_t),
        ("code", uint8_t),
        ("id", uint16_t))

class nfct_l4(Union):
    """
    Layer 4 (tcp, udp, icmp, sctp) informations:
    - port number for tcp, udp and sctp
    - type, code, id for icmp
    """
    _fields_ = (
        ("all", uint16_t),
        ("tcp", _port_struct),
        ("udp", _port_struct),
        ("icmp", _icmp_struct),
        ("sctp", _port_struct))

class nfct_address(Union):
    """
    IPv4 or IPv6 address
    """
    _fields_ = (
        ("v4", uint32_t),
        ("v6", uint32_t * 4))


    def getIPv4(self):
        value = ntohl(self.v4)
        if value < 0:
            return IP(0x100000000 + value)
        else:
            return IP(value)

    def getIPv6(self):
        # TODO: Write the function!
        raise NotImplementedError()
    
    def getIP(self, protonum):
        if protonum == AF_INET:
            return self.getIPv4()
        elif protonum == AF_INET6:
            return self.getIPv6()
        else:
            raise NotImplementedError()

class nfct_tuple(Structure):
    """
    Network information about one connection from INPUT to Netfilter or
    from OUTPUT to Netfilter:
    - source/destination address
    - protocol numbers (layer 3 and 4)
    - layer 4 informations (see nfct_l4)
    """
    _fields_ = (
        ("src", nfct_address),
        ("dst", nfct_address),
        ("l3protonum", uint8_t),
        ("protonum", uint8_t),
        ("l4src", nfct_l4),
        ("l4dst", nfct_l4))

    def write_xml(self, output, indent):
        arg = ['l3protonum="%s"' % self.l3protonum]
        if self.l3protonum == AF_INET:
            arg.append('src="%s"' % self.src.getIPv4())
            arg.append('dst="%s"' % self.dst.getIPv4())
        arg.append('proto="%s"' % self.protonum)
        if self.protonum in (IPPROTO_TCP, IPPROTO_UDP):
            arg.append('sport="%s"' % ntohs(self.l4src.tcp.port))
            arg.append('dport="%s"' % ntohs(self.l4dst.tcp.port))
        output.write('%s<tuple %s />\n' % (indent, " ".join(arg)))

class _protoinfo_tcp(Structure):
    _fields_ = (
        ("state", uint8_t),)

class nfct_protoinfo(Union):
    _fields_ = (
        ("tcp", _protoinfo_tcp),)

class nfct_nat(Structure):
    _fields_ = (
        ("min_ip", uint32_t),
        ("max_ip", uint32_t),
        ("l4min", nfct_l4),
        ("l4max", nfct_l4))

class nfct_counters(Structure):
    _fields_ = (
        ("packets", uint64_t),
        ("bytes", uint64_t))

    def write_xml(self, output, indent):
        output.write('%s<counter packets="%s" bytes="%s" />\n' \
            % (indent, self.packets, self.bytes))

class nfct_conntrack(Structure):
    """
    All informations about one conntrack connection.
    """
    _fields_ = (
        ("tuple", nfct_tuple * NFCT_DIR_MAX),
        ("timeout", uint32_t),
        ("mark", uint32_t),
        ("status", uint32_t),
        ("use", uint32_t),
        ("id", uint32_t),
        ("protoinfo", nfct_protoinfo),
        ("counters", nfct_counters * NFCT_DIR_MAX),
        ("nat", nfct_nat))

    def xmlize(self):
        root = Element("conntrack", id = str(self.id),\
                                    mark = str(self.mark),\
                                    use = str(self.use),\
                                    timeout = str(self.timeout))
        
        # Write status
        status = SubElement(root, "status")
        flags = [ name for mask, name in IPS_NAMES if self.status & mask ]
        for flag in flags:
            SubElement(status, "flag").text = str(flag)
        
        # Write tuples (+ counters)
        for i in range(NFCT_DIR_MAX):
            t = self.tuple[i]
            tuple = SubElement(root, "tuple", direction = str(i))
            SubElement(tuple, "protocol", layer = "3").text = str(t.l3protonum)
            SubElement(tuple, "protocol", layer = "4").text = str(t.protonum)
            SubElement(tuple, "socket", type = "source", \
                                        ip = str(t.src.getIP(t.l3protonum)), \
                                        port = str(t.l4src.tcp.port))
            SubElement(tuple, "socket", type = "destination", \
                                        ip = str(t.dst.getIP(t.l3protonum)), \
                                        port = str(t.l4dst.tcp.port))
            # counters
            SubElement(tuple, "packets").text = str(self.counters[i].packets)
            SubElement(tuple, "bytes").text = str(self.counters[i].bytes)
        return root

    def write_xml(self, output, indent):
        # Write attributes
        output.write('%s<conntrack id="%s" mark="%s" use="%s" timeout="%s">\n' \
            % (indent, self.id, self.mark, self.use, self.timeout))

        # Write status
        indent2 = indent*2
        flags = [ name for mask, name in IPS_NAMES if self.status & mask ]
        if flags:
            indent3 = indent2 + indent
            output.write('%s<status>\n' % indent2)
            for flag in flags:
                output.write('%s<flag>%s</flag>\n' % (indent3, flag))
            output.write('%s</status>\n' % indent2)

        # Write tuples
        use_tuple1 = (self.status & IPS_SRC_NAT) or (self.status & IPS_DST_NAT)
        self.tuple[0].write_xml(output, indent2)
        if use_tuple1:
            self.tuple[1].write_xml(output, indent2)

        # Write counters
        self.counters[0].write_xml(output, indent2)
        if use_tuple1:
            self.counters[1].write_xml(output, indent2)
        output.write('%s</conntrack>\n' % indent)

    def __str__(self):
        orig = self.tuple[0]
        reply = self.tuple[1]
        proto = orig.l3protonum
        text = [ L3PROTONUM_NAMES.get(proto, str(proto)) ]
        if proto == AF_INET:
            text.append(" %s->%s" % (orig.src.getIPv4(), orig.dst.getIPv4()))
        elif proto == AF_INET6:
            text.append(" %s->%s" % (orig.src.getIPv6(), orig.dst.getIPv6()))
        proto = orig.protonum
        text.append(" %s" % IPPROTO_NAMES.get(proto, str(proto)))
        if proto in (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP):
            text.append(" %s->%s" % (ntohs(orig.l4src.tcp.port), ntohs(orig.l4dst.tcp.port)))

        if (self.status & IPS_SRC_NAT) or (self.status & IPS_DST_NAT):
            proto = reply.l3protonum
            text.append(" => %s" % L3PROTONUM_NAMES.get(proto, str(proto)))
            if proto == AF_INET:
                text.append(" %s->%s" % (reply.src.getIPv4(), reply.dst.getIPv4()))
            elif proto == AF_INET6:
                text.append(" %s->%s" % (reply.src.getIPv6(), reply.dst.getIPv6()))
            proto = reply.protonum
            text.append(" %s" % IPPROTO_NAMES.get(proto, str(proto)))
            if proto in (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP):
                text.append(" %s->%s" % (ntohs(reply.l4src.tcp.port), ntohs(reply.l4dst.tcp.port)))
        return "".join(text)

    def sprintf(self):
        buffer = create_string_buffer(512)
        length = nfct_sprintf_conntrack(buffer, byref(self), 0)
        if length:
            return buffer.value
        else:
            raise RuntimeError("sprintf_conntrack failure (%s)." % ok)

class nfct_conntrack_compare(Structure):
    _fields_ = (
        ("ct", nfct_conntrack),
        ("flags", c_uint),
        ("l3flags", c_uint),
        ("l4flags", c_uint))

# ------------------------------- Functions ---------------------------------

# Prototype of a callback. Arguments:
# - conntrack (POINTER(nfct_conntrack)):
#       Pointer to a conntrack entry. The conntrack is a static buffer,
#       so use ctypes_copy() if you would like to store it
# - flags (int):
#       See NFCT_NAMES
# - msg_type (int):
#       Message type: NFCT_MSG_NEW, NFCT_MSG_DESTROY, NFCT_MSG_UPDATE
#       or NFCT_MSG_UNKNOWN
# - data (void*):
#       User data set using nfct_register_callback()
#
# Return: have to return 0
nfct_callback = CFUNCTYPE(c_int, POINTER(nfct_conntrack), c_uint, c_int, POINTER(nfct_conntrack_compare))

# Open the dynamic library
_nfct_library = cdll.LoadLibrary("libnetfilter_conntrack.so.1")

# nfct_open(): open a netfilter handler
nfct_open = _nfct_library.nfct_open
nfct_open.argtypes = (uint8_t, c_uint)
#        nfct_open.restype = nfct_handle_p  # doesn't work!?

# nfct_close(handler): close a netfilter handler
nfct_close = _nfct_library.nfct_close
nfct_close.argtypes = [nfct_handle_p]
nfct_close.restype = c_int

# nfct_sprintf_conntrack(buffer, conntrack, flags) -> length
#    Convert a conntrack to string, see NFCT_NAMES for flags
#    Returns length of the string in bytes (doesn't count the nul byte)
nfct_sprintf_conntrack = _nfct_library.nfct_sprintf_conntrack
nfct_sprintf_conntrack.restype = c_int
nfct_sprintf_conntrack.argtypes = \
    (c_char_p, POINTER(nfct_conntrack), c_uint)

# nfct_register_callback(): setup a callback used by nfct_dump_conntrack_table()
# Convert your Python function to nfct_callback type
# WARNING: callback shouldn't be deleted before
#          nfct_register_callback(hdl, None, None) is called
#          or ctypes will crash
#
# Callback prototype is nfct_callback
nfct_register_callback = _nfct_library.nfct_register_callback
nfct_register_callback.restype = None
nfct_register_callback.argtypes = (nfct_handle_p, c_void_p, c_void_p)

# nfct_dump_conntrack_table(): walk in the connection table
# Use nfct_register_callback() to use callback for each entry
nfct_dump_conntrack_table = _nfct_library.nfct_dump_conntrack_table
nfct_dump_conntrack_table.argtypes = (nfct_handle_p, c_int)
nfct_dump_conntrack_table.restype = c_int

# nfct_get_conntrack()
#    Search a connection using its ID and/or a tuple
# Arguments:
#  - cth (nfct_handle*): NetFilter handler
#  - tuple (nfct_tuple*): A tuple used to select the connection
#  - dir (int): Direction: NFCT_DIR_ORIGINAL or NFCT_DIR_REPLY
#  - id (uint32_t): Connection identifier
# Returns an integer
# Use nfct_register_callback() to set function which will be called on each
# match
nfct_get_conntrack = _nfct_library.nfct_get_conntrack
nfct_get_conntrack.argtypes = (nfct_handle_p, POINTER(nfct_tuple), c_int, uint32_t)
nfct_get_conntrack.restype = c_int

# nfct_update_conntrack()
nfct_update_conntrack = _nfct_library.nfct_update_conntrack
nfct_update_conntrack.argtypes = (nfct_handle_p, POINTER(nfct_conntrack))
nfct_update_conntrack.restype = c_int

# nfct_delete_conntrack()
nfct_delete_conntrack = _nfct_library.nfct_delete_conntrack
nfct_delete_conntrack.argtypes = (nfct_handle_p, POINTER(nfct_tuple), c_int, uint32_t)
nfct_delete_conntrack.restype = int

# -------------------- Python classes ------------------------------------

class ConntrackTable:
    """
    Conntrack table: list of conntrack entries.
    Use "for entry in table" or "table[index]" to get entries.
    Other methods:
    - exportXML(): export table to XML format
    - display(): display table to stdout
    - filter(): extract a part of the table
    """
    def __init__(self, family):
        self._table = []
        self.family = family

    def append(self, entry):
        "Append new conntrack entry to the table"
        self._table.append(entry)

    def __getitem__(self, index):
        "Get an entry by its index"
        return self._table[index]

    def __iter__(self):
        "Iterate on conntrack entries"
        return iter(self._table)

    def __len__(self):
        "Number of conntrack entries in the table"
        return len(self._table)

    def export_xml(self, output, indent="   "):
        output.write('<?xml version="1.0" encoding="ASCII"?>\n')
        output.write('<conntracks>\n')
        for entry in self:
            entry.write_xml(output, indent)
        output.write('</conntracks>\n')

    def display(self, full=False):
        "Display connections to stdout"
        for entry in self:
            print entry
        print "Total: %s connection(s)" % len(self)

    def filter(self, protonum,
    orig_src=None, orig_dst=None,
    reply_src=None, reply_dst=None,
    orig_src_port=None, orig_dst_port=None,
    reply_src_port=None, reply_dst_port=None):
        "Create subset of the table using filter on addresses and ports"
        if orig_src_port:
            orig_src_port = htons(orig_src_port)
        if orig_dst_port:
            orig_dst_port = htons(orig_dst_port)
        if reply_src_port:
            reply_src_port = htons(reply_src_port)
        if reply_dst_port:
            reply_dst_port = htons(reply_dst_port)
        result = ConntrackTable(self.family)
        for entry in self:
            orig = entry.tuple[NFCT_DIR_ORIGINAL]
            reply = entry.tuple[NFCT_DIR_REPLY]
            if orig.protonum != protonum:
                continue
            if self.family == AF_INET6:
                if orig_src and orig.src.getIPv6() not in orig_src:
                    continue
                if orig_dst and orig.dst.getIPv6() not in orig_st:
                    continue
                if reply_src and reply.src.getIPv6() not in reply_src:
                    continue
                if reply_dst and reply.dst.getIPv6() not in reply_st:
                    continue
            else:
                if orig_src and orig.src.getIPv4() not in orig_src:
                    continue
                if orig_dst and orig.dst.getIPv4() not in orig_dst:
                    continue
                if reply_src and reply.src.getIPv4() not in reply_src:
                    continue
                if reply_dst and reply.dst.getIPv4() not in reply_dst:
                    continue
            if protonum in (IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP):
                if orig_src_port and orig.l4src.tcp.port != orig_src_port:
                    continue
                if orig_dst_port and orig.l4dst.tcp.port != orig_dst_port:
                    continue
                if reply_src_port and reply.l4src.tcp.port != reply_src_port:
                    continue
                if reply_dst_port and reply.l4dst.tcp.port != reply_dst_port:
                    continue
            result.append(entry)
        return result

# Function used as callback to append a connection to a connection table.
# You have to assign add_connection_callback.table to your table before using it.
def add_connection_callback(conntrack_p, flags, type, cmp):
    conntrack = ctypes_copy(conntrack_p.contents)
    add_connection_callback.table.append(conntrack)
    return 0

class NetfilterConntrack(object):
    def __init__(self, subsys_id=CONNTRACK | EXPECT, subscriptions=0):
        """
        Open a handler on netfilter.

        subsys_id: use binary and (a | b) with values:
            CONNTRACK: only use conntrack
            EXPECT: only use expect
            CONNTRACK | EXPECT (default): use both

        subscriptions: use binary and (a | b) with values:
            NF_NETLINK_CONNTRACK_NEW
            NF_NETLINK_CONNTRACK_UPDATE
            NF_NETLINK_CONNTRACK_DESTROY
        or use NFCT_ALL_CT_GROUPS (all)
        """
        self.use_conntrack = bool(subsys_id & CONNTRACK)
        self.use_expect = bool(subsys_id & EXPECT)
        if subsys_id == (CONNTRACK | EXPECT):
            subsys_id = 0
        elif subsys_id not in (CONNTRACK, EXPECT):
            raise ValueError("subsys_id value must be CONNTRACK, EXPECT or (CONNTRACK | EXPECT)")
        handler = nfct_open(subsys_id, subscriptions)
        self.handler = nfct_handle_p(handler)
        self.callback = None

    def set_callback(self, func, userdata=None):
        if func is None:
            self.callback = None
            self.callback_data = None
            nfct_register_callback(self.handler, None, None)
        else:
            if not isinstance(func, types.FunctionType):
                raise TypeError("Callback have to be "
                "a classic function or None value, "
                "other types are not supported")
            self.callback = nfct_callback(func)
            self.callback_data = userdata
            nfct_register_callback(self.handler,
                cast(self.callback, c_void_p), self.callback_data)

    def create_table(self, family=AF_INET):
        """
        Create a table (with type ConntrackTable) of all NetFilter connection
        for specified address family.
        """
        if not self.use_conntrack:
            raise RuntimeError("NetfilterConntrack doesn't use conntrack, "
            "needed by nfct_dump_conntrack_table()")

        # Create table and setup our callback to feed the table
        table = ConntrackTable(family)
        add_connection_callback.table = table
        self.set_callback(add_connection_callback)

        # Ask to walk in Netfilter table and call callback for each entry
        nfct_dump_conntrack_table(self.handler, family)

        # Reset the callback and returns the table
        self.set_callback(None)
        return table

    def update_conntrack(self, entry):
        "Update a conntrack entry"
        nfct_update_conntrack(self.handler, entry)

    def delete_conntrack(self, entry):
        "Delete a conntrack entry"
        nfct_delete_conntrack(self.handler, entry.tuple[0], NFCT_DIR_ORIGINAL, entry.id)

    def __del__(self):
        "Close the netfilter handler"
        # Check that handler exist (it doesn't if an exception
        # is raised in constructor)
        if hasattr(self, "handler"):
            nfct_close(self.handler)

