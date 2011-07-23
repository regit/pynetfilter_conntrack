=====================
pynetfilter_conntrack
=====================

libnetfilter_conntrack is a library to manage Linux firewall NetFilter.
pynetfilter_conntrack is a Python binding of this library.  The binding is the
file pynetfilter_conntrack.py and you have also a clone of conntrack program:
conntrack.py.

conntrack.py
============

conntrack.py is a clone of conntrack C program. Features:

 * List connections ;
 * Export connections to XML document ;
 * Delete connection.

For all commands, you can filter connections with:

 * source/destination address from original/reply destination ;
 * layer 3 and 4 protocols ;
 * source/destination port from original/reply destination (protocols tcp,
   udp and sctp).

