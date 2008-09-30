# conntrack attributes
ATTRIBUTES = {
    "orig_ipv4_src": (0, 32),
    "orig_ipv4_dst": (1, 32),
    "repl_ipv4_src": (2, 32),
    "repl_ipv4_dst": (3, 32),
    "orig_ipv6_src": (4, 128),
    "orig_ipv6_dst": (5, 128),
    "repl_ipv6_src": (6, 128),
    "repl_ipv6_dst": (7, 128),
    "orig_port_src": (8, 16),
    "orig_port_dst": (9, 16),
    "repl_port_src": (10, 16),
    "repl_port_dst": (11, 16),
    "icmp_type": (12, 8),
    "icmp_code": (13, 8),
    "icmp_id": (14, 8),
    "orig_l3proto": (15, 8),
    "repl_l3proto": (16, 8),
    "orig_l4proto": (17, 8),
    "repl_l4proto": (18, 8),
    "tcp_state": (19, 8),
    "snat_ipv4": (20, 32),
    "dnat_ipv4": (21, 32),
    "snat_port": (22, 16),
    "dnat_port": (23, 16),
    "timeout": (24, 32),
    "mark": (25, 32),
    "orig_counter_packets": (26, 64),
    "repl_counter_packets": (27, 64),
    "orig_counter_bytes": (28, 64),
    "repl_counter_bytes": (29, 64),
    "use": (30, 32),
    "id": (31, 32),
    "status": (32, 32),
}

# message type
NFCT_T_UNKNOWN = 0
NFCT_T_NEW = (1 << 0)
NFCT_T_UPDATE = (1 << 1)
NFCT_T_DESTROY = (1 << 2)
NFCT_T_ALL = NFCT_T_NEW | NFCT_T_UPDATE | NFCT_T_DESTROY
NFCT_T_ERROR = (1 << 31)

# set option
NFCT_SOPT_UNDO_SNAT = 0
NFCT_SOPT_UNDO_DNAT = 1
NFCT_SOPT_UNDO_SPAT = 2
NFCT_SOPT_UNDO_DPAT = 3
NFCT_SOPT_MAX = NFCT_SOPT_UNDO_DPAT

# get option
NFCT_GOPT_IS_SNAT = 0
NFCT_GOPT_IS_DNAT = 1
NFCT_GOPT_IS_SPAT = 2
NFCT_GOPT_IS_DPAT = 3
NFCT_GOPT_MAX = NFCT_GOPT_IS_DPAT

# callback verdict
NFCT_CB_FAILURE = -1    # failure
NFCT_CB_STOP = 0        # stop the query
NFCT_CB_CONTINUE = 1    # keep iterating through data
NFCT_CB_STOLEN = 2      # like continue, but ct is not freed

# output type
NFCT_O_DEFAULT = 0
NFCT_O_XML = 1

# output flags
NFCT_OF_SHOW_LAYER3 = (1 << 0)

# compare flags
NFCT_MARK = (1 << 3)

# query
NFCT_Q_CREATE = 0
NFCT_Q_UPDATE = 1
NFCT_Q_DESTROY = 2
NFCT_Q_GET = 3
NFCT_Q_FLUSH = 4
NFCT_Q_DUMP = 5
NFCT_Q_DUMP_RESET = 6

# layer 3 protocol families
PF_UNSPEC = 0     # Unspecified
PF_LOCAL = 1      # Local to host (pipes and file-domain)
PF_UNIX = 1       # Old BSD name for PF_LOCAL
PF_FILE = 1       # Another non-standard name for PF_LOCAL
PF_INET = 2       # IP protocol family
PF_AX25 = 3       # Amateur Radio AX.25
PF_IPX = 4        # Novell Internet Protocol
PF_APPLETALK = 5  # Appletalk DDP
PF_NETROM = 6     # Amateur radio NetROM
PF_BRIDGE = 7     # Multiprotocol bridge
PF_ATMPVC = 8     # ATM PVCs
PF_X25 = 9        # Reserved for X.25 project
PF_INET6 = 10     # IP version 6
PF_ROSE = 11      # Amateur Radio X.25 PLP
PF_DECnet = 12    # Reserved for DECnet project
PF_NETBEUI = 13   # Reserved for 802.2LLC project
PF_SECURITY = 14  # Security callback pseudo AF
PF_KEY = 15       # PF_KEY key management API
PF_NETLINK = 16
PF_ROUTE = 16     # Alias to emulate 4.4BSD
PF_PACKET = 17    # Packet family
PF_ASH = 18       # Ash
PF_ECONET = 19    # Acorn Econet
PF_ATMSVC = 20    # ATM SVCs
PF_SNA = 22       # Linux SNA Project
PF_IRDA = 23      # IRDA sockets
PF_PPPOX = 24     # PPPoX sockets
PF_WANPIPE = 25   # Wanpipe API sockets
PF_BLUETOOTH = 31 # Bluetooth sockets
PF_MAX = 32       # For now...

# layer 4 protocols
IPPROTO_IP = 0          # Dummy protocol for TCP
IPPROTO_HOPOPTS = 0     # IPv6 Hop-by-Hop options
IPPROTO_ICMP = 1        # Internet Control Message Protocol
IPPROTO_IGMP = 2        # Internet Group Management Protocol
IPPROTO_IPIP = 4        # IPIP tunnels (older KA9Q tunnels use 94)
IPPROTO_TCP = 6         # Transmission Control Protocol
IPPROTO_EGP = 8         # Exterior Gateway Protocol
IPPROTO_PUP = 12        # PUP protocol
IPPROTO_UDP = 17        # User Datagram Protocol
IPPROTO_IDP = 22        # XNS IDP protocol
IPPROTO_TP = 29         # SO Transport Protocol Class 4
IPPROTO_IPV6 = 41       # IPv6-in-IPv4 tunnelling
IPPROTO_ROUTING = 43    # IPv6 routing header
IPPROTO_FRAGMENT = 44,  # IPv6 fragmentation header
IPPROTO_RSVP = 46       # RSVP protocol
IPPROTO_GRE = 47        # Cisco GRE tunnels (rfc 1701,1702)
IPPROTO_ESP = 50        # Encapsulation Security Payload protocol
IPPROTO_AH = 51         # Authentication Header protocol
IPPROTO_ICMPV6 = 58     # ICMPv6
IPPROTO_NONE = 59       # IPv6 no next header
IPPROTO_DSTOPTS = 60    # IPv6 destination options
IPPROTO_MTP = 92        # Multicast Transport Protocol
IPPROTO_ENCAP = 98      # Encapsulation Header
IPPROTO_PIM = 103       # Protocol Independent Multicast
IPPROTO_COMP = 108      # Compression Header protocol
IPPROTO_SCTP = 132      # Stream Control Transport Protocol
IPPROTO_RAW = 255

# tcp state
NFCT_TCP_ST_NONE = 0
NFCT_TCP_ST_SYN_SENT = 1
NFCT_TCP_ST_SYN_RECV = 2
NFCT_TCP_ST_ESTABLISHED = 3
NFCT_TCP_ST_FIN_WAIT = 4
NFCT_TCP_ST_CLOSE_WAIT = 5
NFCT_TCP_ST_LAST_ACK = 6
NFCT_TCP_ST_TIME_WAIT = 7
NFCT_TCP_ST_CLOSE = 8
NFCT_TCP_ST_LISTEN = 9

# Netfilter subsystem identifier (libnfnetlink/linux_nfnetlink.h)
CONNTRACK = NFNL_SUBSYS_CTNETLINK = 1
EXPECT = NFNL_SUBSYS_CTNETLINK_EXP = 2


### Bitset representing status of connection ################################

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

# nfnetlink groups: Up to 32 maximum - backwards compatibility for userspace
NF_NETLINK_CONNTRACK_NEW         = 0x00000001
NF_NETLINK_CONNTRACK_UPDATE      = 0x00000002
NF_NETLINK_CONNTRACK_DESTROY     = 0x00000004
NF_NETLINK_CONNTRACK_EXP_NEW     = 0x00000008
NF_NETLINK_CONNTRACK_EXP_UPDATE  = 0x00000010
NF_NETLINK_CONNTRACK_EXP_DESTROY = 0x00000020
NFCT_ALL_CT_GROUPS = (NF_NETLINK_CONNTRACK_NEW \
    | NF_NETLINK_CONNTRACK_UPDATE | NF_NETLINK_CONNTRACK_DESTROY)

##__all__ = (
##    "ATTRIBUTES",
##    "NFCT_Q_CREATE", "NFCT_Q_UPDATE", "NFCT_Q_DESTROY", "NFCT_Q_GET",
##    "NFCT_Q_FLUSH", "NFCT_Q_DUMP", "NFCT_Q_DUMP_RESET",
##    "NFCT_T_UNKNOWN", "NFCT_T_NEW", "NFCT_T_UPDATE", "NFCT_T_DESTROY",
##    "NFCT_T_ALL", "NFCT_T_ERROR",
##    "CONNTRACK", "EXPECT",
##    "NFCT_OF_SHOW_LAYER3", "NFCT_O_DEFAULT", "NFCT_O_XML",
##    "NFCT_CB_FAILURE", "NFCT_CB_STOP", "NFCT_CB_CONTINUE", "NFCT_CB_STOLEN",
##    "IPS_EXPECTED", "IPS_SEEN_REPLY", "IPS_ASSURED", "IPS_CONFIRMED",
##    "IPS_SRC_NAT", "IPS_DST_NAT", "IPS_NAT_MASK", "IPS_SEQ_ADJUST",
##    "IPS_SRC_NAT_DONE", "IPS_DST_NAT_DONE", "IPS_NAT_DONE_MASK",
##    "IPS_DYING", "IPS_FIXED_TIMEOUT",
##    "PF_UNSPEC", "PF_LOCAL", "PF_UNIX", "PF_FILE", "PF_INET", "PF_AX25",
##    "PF_IPX", "PF_APPLETALK", "PF_NETROM", "PF_BRIDGE", "PF_ATMPVC", "PF_X25",
##    "PF_INET6", "PF_ROSE", "PF_DECnet", "PF_NETBEUI", "PF_SECURITY", "PF_KEY",
##    "PF_NETLINK", "PF_ROUTE", "PF_PACKET", "PF_ASH", "PF_ECONET", "PF_ATMSVC",
##    "PF_SNA", "PF_IRDA", "PF_PPPOX", "PF_WANPIPE", "PF_BLUETOOTH", "PF_MAX",
##    "IPPROTO_IP", "IPPROTO_HOPOPTS", "IPPROTO_ICMP", "IPPROTO_IGMP",
##    "IPPROTO_IPIP", "IPPROTO_TCP", "IPPROTO_EGP", "IPPROTO_PUP", "IPPROTO_UDP",
##    "IPPROTO_IDP", "IPPROTO_TP", "IPPROTO_IPV6", "IPPROTO_ROUTING",
##    "IPPROTO_FRAGMENT", "IPPROTO_RSVP", "IPPROTO_GRE", "IPPROTO_ESP",
##    "IPPROTO_AH", "IPPROTO_ICMPV6", "IPPROTO_NONE", "IPPROTO_DSTOPTS",
##    "IPPROTO_MTP", "IPPROTO_ENCAP", "IPPROTO_PIM", "IPPROTO_COMP",
##    "IPPROTO_SCTP", "IPPROTO_RAW",
##)

# tcp_state
TCP_CONNTRACK_NONE = 0
TCP_CONNTRACK_SYN_SENT = 1
TCP_CONNTRACK_SYN_RECV = 2
TCP_CONNTRACK_ESTABLISHED = 3
TCP_CONNTRACK_FIN_WAIT = 4
TCP_CONNTRACK_CLOSE_WAIT = 5
TCP_CONNTRACK_LAST_ACK = 6
TCP_CONNTRACK_TIME_WAIT = 7
TCP_CONNTRACK_CLOSE = 8
TCP_CONNTRACK_LISTEN = 9
TCP_CONNTRACK_MAX = 10
TCP_CONNTRACK_IGNORE = 11

# set option
NFCT_SOPT_UNDO_SNAT = 0
NFCT_SOPT_UNDO_DNAT = 1
NFCT_SOPT_UNDO_SPAT = 2
NFCT_SOPT_UNDO_DPAT = 3
NFCT_SOPT_SETUP_ORIGINAL = 4
NFCT_SOPT_SETUP_REPLY = 5

