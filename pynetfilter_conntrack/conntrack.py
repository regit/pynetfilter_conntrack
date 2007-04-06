from pynetfilter_conntrack import ConntrackEntry,\
    nfct_new, nfct_destroy, nfct_open, nfct_close, nfct_query,\
    nfct_callback_t, nfct_callback_register, nfct_callback_unregister,\
    nfct_snprintf,\
    CONNTRACK, NFCT_Q_DUMP, NFCT_T_ALL, NFCT_CB_STOLEN,\
    NFCT_Q_DESTROY
from ctypes import byref
from pynetfilter_conntrack.ctypes_stdint import uint8_t
from os import strerror
from pynetfilter_conntrack.ctypes_errno import get_errno
from socket import AF_INET

class Conntrack:
    def __init__(self, subsys=CONNTRACK, subscriptions=0):
        """
        Create new conntrack object. May raise a RuntimeError.
        """
        
        # Callback things
        self.callback = None
        self.callback_arg = None
        
        # Default value, needed by __del__ if an exception is raised in the constructor
        self.conntrack = None
        self.handle = None
        
        # Open a conntrack handler
        self.handle = nfct_open(subsys, subscriptions)
        if not self.handle:
            raise RuntimeError("nfct_new() failure: %s" % strerror(get_errno()))

    def __del__(self):
        """Destroy conntrack object"""
        if self.handle:
            nfct_close(self.handle)

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

    def destroy_conntrack(self, entry):
        """
        Destroy (kill) a connection in the conntrack table,
        entry type is 'ConntrackEntry'.
        """
        self.query(NFCT_Q_DESTROY, entry.conntrack)

    def dump_table(self, family=AF_INET, event_type=NFCT_T_ALL):
        # Create a pointer to a 'uint8_t' of the address family
        family = byref(uint8_t(family))
        
        def copyEntry(msgtype, ct, data):
            copyEntry.ctlist.append(ConntrackEntry(self, ct, msgtype))
            return NFCT_CB_STOLEN
        copyEntry.ctlist = []
        
        # Install callback, do the query, remove callback
        self.register_callback(copyEntry, event_type)
        self.query(NFCT_Q_DUMP, family)
        self.unregister_callback()
        return copyEntry.ctlist

    def query(self, command, argument):
        """
        Do query libnetfilter_conntrack:
         - command: NFCT_Q_CREATE, NFCT_Q_UPDATE, ...
         - argument (optional): value depends on command
        
        May raise a RuntimeError.
        """
        ret = nfct_query(self.handle, command, argument)
        if ret != 0:
            raise RuntimeError("nfct_query() failure: %s" % strerror(get_errno()))

__all__ = ("Conntrack", )

