# conntrack attributes
ATTRIBUTES = {
    "orig_ipv4_src": (0, 32),
    "orig_ipv4_dst": (1, 32),
    "repl_ipv4_src": (2, 32),
    "repl_ipv4_dst": (3, 32),
    "orig_ipv6_src": (4, 128),   # FIXME: type is ipv6,
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

# query
NFCT_Q_CREATE = 0
NFCT_Q_UPDATE = 1
NFCT_Q_DESTROY = 2
NFCT_Q_GET = 3
NFCT_Q_FLUSH = 4
NFCT_Q_DUMP = 5
NFCT_Q_DUMP_RESET = 6

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

__all__ = (
    "ATTRIBUTES",
    "NFCT_Q_CREATE", "NFCT_Q_UPDATE", "NFCT_Q_DESTROY", "NFCT_Q_GET",
    "NFCT_Q_FLUSH", "NFCT_Q_DUMP", "NFCT_Q_DUMP_RESET",
    "NFCT_T_UNKNOWN", "NFCT_T_NEW", "NFCT_T_UPDATE", "NFCT_T_DESTROY",
    "NFCT_T_ALL", "NFCT_T_ERROR",
    "CONNTRACK", "EXPECT",
    "NFCT_OF_SHOW_LAYER3", "NFCT_O_DEFAULT", "NFCT_O_XML",
    "NFCT_CB_FAILURE", "NFCT_CB_STOP", "NFCT_CB_CONTINUE", "NFCT_CB_STOLEN",
    "IPS_EXPECTED", "IPS_SEEN_REPLY", "IPS_ASSURED", "IPS_CONFIRMED",
    "IPS_SRC_NAT", "IPS_DST_NAT", "IPS_NAT_MASK", "IPS_SEQ_ADJUST",
    "IPS_SRC_NAT_DONE", "IPS_DST_NAT_DONE", "IPS_NAT_DONE_MASK",
    "IPS_DYING", "IPS_FIXED_TIMEOUT",
)

