from pynetfilter_conntrack import \
    IPPROTO_TCP, TCP_CONNTRACK_TIME_WAIT, PF_INET, PF_INET6

class Filter:
    def __init__(self):
        self.start = 0
        self.size = None
        self.reverse = False
        self.sort = "orig_ipv4_src"
        self.drop_networks = None

    def filterConnection(self, conn):
        # Ignore TCP connection in state TIME_WAIT
        if (conn.orig_l4proto == IPPROTO_TCP) \
        and (conn.tcp_state == TCP_CONNTRACK_TIME_WAIT):
            return False

        # Get source and destination IP (v4 or v6) addresses
        l3proto = conn.orig_l3proto
        if l3proto == PF_INET:
            ip_src = conn.orig_ipv4_src
            ip_dst = conn.orig_ipv4_dst
        elif l3proto == PF_INET6:
            ip_src = conn.orig_ipv6_src
            ip_dst = conn.orig_ipv6_dst
        else:
            return True

        # Ignore IP address in self.filter
        if self.drop_networks:
            for network in self.drop_networks:
                if (ip_src in network) or (ip_dst in network):
                    return False
        return True

    def createCNetfilterOptions(self):
        if not self.size:
            size = 0
        else:
            size = self.size
        options = {
            'start': self.start,
            'size': size,
            'reverse': self.reverse,
            'sort': self.sort,
        }
        if self.drop_networks:
            options['drop_networks'] = tuple((ip.int(), ip.broadcast().int()) for ip in self.drop_networks)
        return options

    def truncate(self, connset):
        if self.size is not None:
            return connset[self.start:self.start + self.size]
        else:
            return connset[self.start:]

    def sortKey(self, conn):
        return getattr(conn, self.sort)

    def sortTable(self, connset):
        connset.sort(key=self.sortKey, reverse=self.reverse)

