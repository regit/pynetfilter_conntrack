#!/usr/bin/env python

from pynetfilter_conntrack import Conntrack, NFCT_O_DEFAULT, NFCT_O_XML
from socket import AF_INET
import sys

OUTPUT_FORMAT = {
    "list": NFCT_O_DEFAULT,
    "xml": NFCT_O_XML,
}

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in OUTPUT_FORMAT:
        print >>sys.stderr, "usage: %s command" % sys.argv[0]
        print >>sys.stderr
        print >>sys.stderr, "command: list or xml"
        sys.exit(1)
    mode = sys.argv[1]
    output = OUTPUT_FORMAT[mode]

    try:
        if mode == "xml":
            print '<?xml version="1.0" encoding="ISO-8859-1"?>'
            print '<flows>'
        nf = Conntrack()
        table = nf.dump_table(AF_INET)
        for entry in table:
            print entry.format(output)
        if mode == "xml":
            print '</flows>'
    except RuntimeError, err:
        print "ERROR: %s" % err
    except KeyboardInterrupt:
        print "Interrupted."

if __name__ == "__main__":
    main()

