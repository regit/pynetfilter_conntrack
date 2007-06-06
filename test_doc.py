#!/usr/bin/env python
import doctest
import sys

def test(name):
    mod = __import__(name)
    for subname in name.split(".")[1:]:
        mod = getattr(mod, subname)
    print "=== Test %s ===" % mod.__name__
    failure, tests = doctest.testmod(mod)
    return failure

def main():
    failure = test("pynetfilter_conntrack.tools")
    if not failure:
        print "Everything is ok"
        sys.exit(0)
    else:
        print "Total: %u failure" % failure
        sys.exit(1)

if __name__ == "__main__":
    main()

