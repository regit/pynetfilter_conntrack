from pynetfilter_conntrack.tools import reverse_dict
from socket import AF_INET, AF_INET6

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


