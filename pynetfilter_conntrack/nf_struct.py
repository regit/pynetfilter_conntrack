from ctypes import Union, Structure, \
    c_void_p, c_uint, \
    byref, create_string_buffer
from pynetfilter_conntrack.ctypes_stdint import uint8_t, uint16_t, uint32_t, uint64_t
from pynetfilter_conntrack.constant import \
    IPPROTO_TCP, IPPROTO_UDP, IPPROTO_SCTP, IPPROTO_NAMES, \
    NFCT_DIR_MAX, L3PROTONUM_NAMES, \
    IPS_SRC_NAT, IPS_SRC_NAT, IPS_DST_NAT, IPS_NAMES
from socket import ntohs, ntohl, AF_INET, AF_INET6
from IPy import IP
try:
    from cElementTree import Element, SubElement
except ImportError:
    from elementtree.ElementTree import Element, SubElement

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

    def getValue(self, protonum):
        if protonum == IPPROTO_TCP:
            return self.tcp.port
        if protonum == IPPROTO_UDP:
            return self.udp.port
        if protonum == IPPROTO_ICMP:
            return self.icmp.type
        raise NotImplementedError()

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
        # TODO: Write the function
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
            raise RuntimeError("sprintf_conntrack failure.")


class nfct_conntrack_compare(Structure):
    _fields_ = (
        ("ct", nfct_conntrack),
        ("flags", c_uint),
        ("l3flags", c_uint),
        ("l4flags", c_uint))

__all__ = (
    "nfct_handle_p",
    "nfct_l4", "nfct_address", "nfct_tuple", "nfct_protoinfo",
    "nfct_nat", "nfct_counters", "nfct_conntrack", "nfct_conntrack_compare",
)
