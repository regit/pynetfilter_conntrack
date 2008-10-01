from pynetfilter_conntrack import ConntrackEntry, Filter, \
    nfct_query, nfct_callback_t, nfct_callback_register, \
    nfct_callback_unregister, nfct_catch, \
    CONNTRACK, NFCT_Q_DUMP, NFCT_T_ALL, NFCT_CB_CONTINUE, NFCT_CB_STOLEN
from pynetfilter_conntrack.conntrack_base import ConntrackBase
from ctypes import byref
from pynetfilter_conntrack.ctypes_stdint import uint8_t
from socket import AF_INET
try:
    from cnetfilter_conntrack import dump_table_ipv4
    HAS_CNETFILTER_CONNTRACK = True
except ImportError, err:
    HAS_CNETFILTER_CONNTRACK = False
from IPy import IP

class Conntrack(ConntrackBase):
    def __init__(self, subscriptions=0, subsys=CONNTRACK):
        ConntrackBase.__init__(self, subsys, subscriptions)

    def register_callback(self, callback, event_type=NFCT_T_ALL, data=None):
        """
        Register a callback, needed by some query.
        Callback prototype is: func(msgtype, ct, data), the callback have to
        return: NFCT_CB_CONTINUE, NFCT_CB_FAILURE, NFCT_CB_STOP,
        or NFCT_CB_STOLEN (like continue, but ct is not freed).
        """
        self.callback = nfct_callback_t(callback)
        self.callback_arg = data
        nfct_callback_register(self.handle, event_type, self.callback, self.callback_arg)

    def unregister_callback(self):
        """Unregister callback"""
        nfct_callback_unregister(self.handle)
        self.callback = None
        self.callback_arg = None

    def dump_table(self, family=AF_INET, event_type=NFCT_T_ALL, filter=None):
        if not filter:
            filter = Filter()
        if HAS_CNETFILTER_CONNTRACK:
            if family != AF_INET:
                raise ValueError("cnetfilter_conntrack only supports IPv4")
            options = filter.createCNetfilterOptions()
            table, total = dump_table_ipv4(self.handle, **options)

            connections = []
            for attr in table:
                handle = attr.pop('handle')
                for key, value in attr.iteritems():
                    if "ipv4" in key:
                        attr[key] = IP(value)
                conn = ConntrackEntry(self, handle, attr=attr)
                connections.append(conn)

            return connections, total
        else:
            # Create a pointer to a 'uint8_t' of the address family
            family = byref(uint8_t(family))

            def copyEntry(msgtype, conntrack, data):
                conn = ConntrackEntry(self, conntrack, msgtype)
                if not filter.filterConnection(conn):
                    conn._destroy = False
                    return NFCT_CB_CONTINUE
                copyEntry.ctlist.append(conn)
                return NFCT_CB_STOLEN
            copyEntry.ctlist = []

            # Install callback, do the query, remove callback
            self.register_callback(copyEntry, event_type)
            self.query(NFCT_Q_DUMP, family)
            self.unregister_callback()
            connset = copyEntry.ctlist

            # Sort the list
            filter.sortTable(connset)

            # Truncated the list
            total = len(connset)
            connset = filter.truncate(connset)

            # Suppress unwanted entries
            return connset, total

    def query(self, command, argument):
        """
        Do query libnetfilter_conntrack:
         - command: NFCT_Q_CREATE, NFCT_Q_UPDATE, ...
         - argument (optional): value depends on command

        May raise a RuntimeError.
        """
        ret = nfct_query(self.handle, command, argument)
        if ret != 0:
            self._error('nfct_query')

    def catch(self, callback):
        """
        Catch all Netfilter events: call specified callback for each event.
        See register_callback() method for callback details.
        """
        self.register_callback(callback)
        ret = nfct_catch(self.handle)
        if ret != 0:
            self._error('nfct_catch')
        self.unregister_callback()

__all__ = ("Conntrack", "HAS_CNETFILTER_CONNTRACK")

