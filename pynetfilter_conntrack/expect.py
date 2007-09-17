from pynetfilter_conntrack import ExpectEntry,\
    nfexp_callback_t,\
    nfexp_query, nfexp_callback_register,\
    nfexp_callback_unregister, nfexp_catch,\
    NFCT_Q_DUMP, NFCT_Q_FLUSH, NFCT_T_ALL, EXPECT,\
    NFCT_CB_STOLEN
from pynetfilter_conntrack.ctypes_stdint import uint8_t
from ctypes import byref
from socket import AF_INET
from pynetfilter_conntrack.ctypes_errno import get_errno
from os import strerror
from pynetfilter_conntrack.conntrack_base import ConntrackBase

class Expect(ConntrackBase):
    def __init__(self, subscriptions=0, subsys=EXPECT):
        ConntrackBase.__init__(self, subsys, subscriptions)

    def register_callback(self, callback, event_type=NFCT_T_ALL, data=None):
        """
        Register a callback, needed by some query.
        Callback Python prototype is: func(msgtype, exp, data), C prototype:
           int cb(enum nf_conntrack_msg_type type,
                  struct nf_expect *exp,
                  void *data)

        The callback have to return: NFCT_CB_CONTINUE, NFCT_CB_FAILURE,
        NFCT_CB_STOP, or NFCT_CB_STOLEN (like continue, but ct is not freed).
        """
        self.callback = nfexp_callback_t(callback)
        self.callback_arg = data
        nfexp_callback_register(self.handle, event_type, self.callback, self.callback_arg)

    def unregister_callback(self):
        """Unregister callback"""
        nfexp_callback_unregister(self.handle)
        self.callback = None
        self.callback_arg = None

    def query(self, command, argument):
        """
        Do query libnetfilter_conntrack:
         - command: NFCT_Q_CREATE, NFCT_Q_UPDATE, ...
         - argument (optional): value depends on command

        May raise a RuntimeError.
        """
        ret = nfexp_query(self.handle, command, argument)
        if ret != 0:
            raise RuntimeError("nfct_query() failure: %s" % strerror(get_errno()))

    def dump_table(self, family=AF_INET, event_type=NFCT_T_ALL):
        # Create a pointer to a 'uint8_t' of the address family
        family = byref(uint8_t(family))

        def copyEntry(msgtype, ct, data):
            copyEntry.ctlist.append(ExpectEntry(self, ct, msgtype))
            return NFCT_CB_STOLEN
        copyEntry.ctlist = []

        # Install callback, do the query, remove callback
        self.register_callback(copyEntry, event_type)
        self.query(NFCT_Q_DUMP, family)
        self.unregister_callback()
        return copyEntry.ctlist

    def flush(self, family=AF_INET):
        family = byref(uint8_t(family))
        self.query(NFCT_Q_FLUSH, family)

    def catch(self, callback):
        """
        Catch all Netfilter expect events: call specified callback for
        each event. See register_callback() method for callback details.
        """
        self.register_callback(callback)
        ret = nfexp_catch(self.handle)
        if ret != 0:
            raise RuntimeError("nfexp_catch() failure: %s" % strerror(get_errno()))

__all__ = ('Expect', )

