#!/usr/bin/env python

from pynetfilter_conntrack import Conntrack
from socket import AF_INET

def main():
    nf = Conntrack()
    table = nf.dump_table(AF_INET)
    for entry in table:
        entry.mark = 42
        entry.update()

    table = nf.dump_table(AF_INET)
    for entry in table:
        print entry

if __name__ == "__main__":
    main()

