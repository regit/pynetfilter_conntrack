#!/usr/bin/env python
from pynetfilter_conntrack import (
    Conntrack, Expect, ExpectEntry, ConntrackEntry,
    NFCT_Q_FLUSH, NFCT_Q_CREATE, NF_NETLINK_CONNTRACK_EXP_NEW,
    NFCT_CB_STOP, NFCT_CB_CONTINUE,
    TCP_CONNTRACK_LISTEN, IPPROTO_TCP,
    NFCT_SOPT_SETUP_REPLY,
    CONNTRACK, EXPECT)
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
    print "create"
    conntrack = Conntrack()
    entry = ConntrackEntry.new(conntrack)

    print "setup"
    entry.orig_l3proto = AF_INET
    entry.orig_ipv4_src = IP("172.16.127.201")
    entry.orig_ipv4_dst = IP("204.152.191.37")
    entry.orig_l4proto = IPPROTO_TCP
    entry.orig_port_src = 1025
    entry.orig_port_dst = 21
    entry.setobjopt(NFCT_SOPT_SETUP_REPLY)
    entry.tcp_state = TCP_CONNTRACK_LISTEN
    entry.timeout = 200
    print "query"
    print entry
    conntrack.query(NFCT_Q_CREATE, entry._handle)

def create_expect(expect):
    print "create"
    entry = ExpectEntry.new(expect)
    print "create: setup"
    entry.orig_l3proto = AF_INET
    entry.orig_ipv4_src = IP("172.16.127.201")
    entry.orig_ipv4_dst = IP("204.152.191.37")
    entry.orig_l4proto = IPPROTO_TCP
    entry.orig_port_src = 0
    entry.orig_port_dst = 41491
    #nfct_setobjopt(master, NFCT_SOPT_SETUP_REPLY)
    entry.status = TCP_CONNTRACK_LISTEN
    entry.timeout = 200
    print "query"
    conntrack.query(NFCT_Q_CREATE, entry._handle)

def main():
    # Create
    create_conntrack()
    #expect = Expect()
    #test_create(expect)
    return

    # Watch events
#    try:
#        conntrack.catch(event_cb)
#    except KeyboardInterrupt:
#        print "Interrupted."

    # Dump table
    table = conntrack.dump_table()
    for entry in table:
        print entry

main()
