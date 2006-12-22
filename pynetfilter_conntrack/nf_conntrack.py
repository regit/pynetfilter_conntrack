from types import FunctionType
from ctypes import byref, cast, c_void_p
from socket import htons, AF_INET, AF_INET6
from pynetfilter_conntrack import \
    CONNTRACK, EXPECT, \
    NFCT_DIR_ORIGINAL, NFCT_DIR_REPLY, NFCT_DIR_MAX, \
    IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP, \
    nfct_handle_p, nfct_open, nfct_close, \
    nfct_callback, nfct_register_callback, \
    nfct_dump_conntrack_table, nfct_update_conntrack, nfct_delete_conntrack, \
    ctypes_copy

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

    def __getstate__(self):
        "Save object instance for pickle"
        root = {}
        root["family"] = self.family
        conntab = []
        for conn in self._table:
            conntrack = {}
            conntrack["id"] = int(conn.id)
            conntrack["mark"] = int(conn.mark)
            conntrack["use"] = int(conn.use)
            conntrack["timeout"] = int(conn.timeout)
            conntrack["status"] = int(conn.status)
            ttab = []
            ctab = []
            for i in range(NFCT_DIR_MAX):
                t = conn.tuple[i]
                tuple = {}
                tuple["l3protonum"] = int(t.l3protonum)
                tuple["protonum"] = int(t.protonum)
                if t.l3protonum == AF_INET:
                    tuple["src"] = int(t.src.v4)
                    tuple["dst"] = int(t.dst.v4)
                else: # protonum == AF_INET6:
                    tuple["src"] = str(":".join(t.src.v6))
                    tuple["dst"] = str(":".join(t.dst.v6))
                tuple["l4src"] = int(t.l4src.tcp.port)
                tuple["l4dst"] = int(t.l4dst.tcp.port)
                ttab.append(tuple)
                c = conn.counters[i]
                counter = {}
                counter["packets"] = int(c.packets)
                counter["bytes"] = int(c.bytes)
                ctab.append(counter)
            conntrack["tuples"] = ttab
            conntrack["counters"] = ctab
            conntrack["protoinfo"] = conn.protoinfo.tcp.state
            nat = {}
            nat["max_ip"] = int(conn.nat.max_ip)
            nat["min_ip"] = int(conn.nat.min_ip)
            nat["l4max"] = int(conn.nat.l4max.tcp.port)
            nat["l4min"] = int(conn.nat.l4min.tcp.port)
            conntrack["nat"] = nat
            conntab.append(conntrack)
        root["table"] = conntab
        return root

    def __setstate__(self, root):
        "Restore object instance from pickle"
        self.family = root["family"]
        self._table = []
        for conntrack in root["table"]:

            conn = nfct_conntrack()
            conn.id = conntrack["id"]
            conn.mark = conntrack["mark"]
            conn.use = conntrack["use"]
            conn.timeout = conntrack["timeout"]
            conn.status = conntrack["status"]
            ttab = []
            for etuple in conntrack["tuples"]:
                t = nfct_tuple()
                t.l3protonum = etuple["l3protonum"]
                t.protonum = etuple["protonum"]

                if t.l3protonum == AF_INET:
                    t.src = nfct_address(v4=etuple["src"])
                    t.dst = nfct_address(v4=etuple["dst"])
                else: # protonum == AF_INET6:
                    t.src = nfct_address(v6=etuple["src"].split(":"))
                    t.dst = nfct_address(v6=etuple["dst"].split(":"))
                t.l4src = nfct_l4(tcp=_port_struct(etuple["l4src"]))
                t.l4dst = nfct_l4(tcp=_port_struct(etuple["l4dst"]))
                ttab.append(t)
            conn.tuple = tuple(ttab)
            ctab = []
            for counter in conntrack["counters"]:
                c = nfct_counters()
                c.packets = counter["packets"]
                c.bytes = counter["bytes"]
                ctab.append(c)
            conn.counters = tuple(ctab)
            conn.protoinfo = nfct_protoinfo(tcp=_protoinfo_tcp(conntrack["protoinfo"]))
            nat = conntrack["nat"]
            conn.nat = nfct_nat()
            conn.nat.max_ip = nat["max_ip"]
            conn.nat.min_ip = nat["min_ip"]
            conn.nat.l4max = nfct_l4(tcp=_port_struct(nat["l4max"]))
            conn.nat.l4min = nfct_l4(tcp=_port_struct(nat["l4min"]))
            self._table.append(conn)

    def export_xml(self, output, indent="   "):
        output.write('<?xml version="1.0" encoding="ASCII"?>\n')
        output.write('<conntracks>\n')
        for entry in self:
            entry.write_xml(output, indent)
        output.write('</conntracks>\n')

    def display(self):
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
                if orig_dst and orig.dst.getIPv6() not in orig_dst:
                    continue
                if reply_src and reply.src.getIPv6() not in reply_src:
                    continue
                if reply_dst and reply.dst.getIPv6() not in reply_dst:
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
            if not isinstance(func, FunctionType):
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
        """Update a conntrack entry
        @type entry: nfct_conntrack"""
        nfct_update_conntrack(self.handler, byref(entry))

    def delete_conntrack(self, entry):
        """Delete a conntrack entry
        @type entry: nfct_conntrack
        """
        nfct_delete_conntrack(self.handler, byref(entry.tuple[0]), NFCT_DIR_ORIGINAL, entry.id)

    def __del__(self):
        "Close the netfilter handler"
        # Check that handler exist (it doesn't if an exception
        # is raised in constructor)
        if hasattr(self, "handler"):
            nfct_close(self.handler)

__all__ = ("ConntrackTable", "NetfilterConntrack")
