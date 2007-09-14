#!/usr/bin/env python
from pynetfilter_conntrack import (
    Conntrack, Expect, ExpectEntry, ConntrackEntry,
    NFCT_Q_FLUSH, NF_NETLINK_CONNTRACK_EXP_NEW,
    NFCT_CB_STOP, NFCT_CB_CONTINUE,
    TCP_CONNTRACK_LISTEN, IPPROTO_TCP,
    NFCT_SOPT_SETUP_REPLY,
    CONNTRACK, EXPECT,
    nfexp_set_attr, nfexp_set_attr_u32)
from socket import AF_INET
from IPy import IP

counter = 0

def event_cb(msgtype, ct, data):
    global counter
    counter += 1
    if 2 <= counter:
        return NFCT_CB_STOP

    entry = ExpectEntry(data, ct, msgtype, destroy=False)
    print entry

    return NFCT_CB_CONTINUE

def create_conntrack():
    # ----------- create conntrack entry -----------
    conntrack = Conntrack()

    master = ConntrackEntry.new(conntrack)
    master.orig_l3proto = AF_INET
    master.orig_ipv4_src = IP("172.16.127.201")
    master.orig_ipv4_dst = IP("204.152.191.36")
    master.orig_l4proto = IPPROTO_TCP
    master.orig_port_src = 1025
    master.orig_port_dst = 21
    master.setobjopt(NFCT_SOPT_SETUP_REPLY)
    master.tcp_state = TCP_CONNTRACK_LISTEN
    master.timeout = 10
    master.create()

    # ----------- create expect entry -----------
    expect = Expect()

    expected = ConntrackEntry.new(expect)
    expected.orig_l3proto = AF_INET
    expected.orig_ipv4_src = IP("172.16.127.201")
    expected.orig_ipv4_dst = IP("204.152.191.36")
    expected.orig_l4proto = IPPROTO_TCP
    expected.orig_port_src = 10240
    expected.orig_port_dst = 10241

    mask = ConntrackEntry.new(expect)
    mask.orig_l3proto = AF_INET
    mask.orig_ipv4_src = 0xffffffff
    mask.orig_ipv4_dst = 0xffffffff
    mask.orig_l4proto = IPPROTO_TCP
    mask.orig_port_src = 0xffff
    mask.orig_port_dst = 0xffff

    print "add"
    exp = ExpectEntry.new(expect)
    ATTR_EXP_MASTER = 0
    ATTR_EXP_EXPECTED = 1
    ATTR_EXP_MASK = 2
    ATTR_EXP_TIMEOUT = 3
    nfexp_set_attr(exp._handle, ATTR_EXP_MASTER, master._handle)
    nfexp_set_attr(exp._handle, ATTR_EXP_EXPECTED, expected._handle)
    nfexp_set_attr(exp._handle, ATTR_EXP_MASK, mask._handle)
    nfexp_set_attr_u32(exp._handle, ATTR_EXP_TIMEOUT, 200)
    print "FINAL: Create entry"
    exp.create()

def flush_expect():
    expect = Expect()
    expect.flush()

def dump_expect():
    expect = Expect()
    for entry in expect.dump_table():
        print entry

def watch_expect():
    try:
        expect = Expect()
        expect.catch(event_cb)
    except KeyboardInterrupt:
        print "Interrupted."

def main():
    flush_expect()
    create_conntrack()
    #create_expect()
    dump_expect()
    #watch_expect()

main()
