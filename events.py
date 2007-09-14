#!/usr/bin/env python
from pynetfilter_conntrack import (Conntrack, ConntrackEntry,
    NFCT_ALL_CT_GROUPS,
    NFCT_CB_STOP, NFCT_CB_CONTINUE)
from socket import AF_INET
import sys

counter = 0

def event_cb(msgtype, ct, data):
    global counter
    counter += 1
    if 10 <= counter:
        return NFCT_CB_STOP

    entry = ConntrackEntry(data, ct, msgtype, destroy=False)
    print entry

    return NFCT_CB_CONTINUE

def main():
    conntrack = Conntrack(subscriptions=NFCT_ALL_CT_GROUPS)
    event_cb.conntrack = conntrack
    try:
        conntrack.catch(event_cb)
    except KeyboardInterrupt:
        print "Interrupted."

main()
