from pynetfilter_conntrack import \
    nfct_open, nfct_close

class ConntrackBase(object):
    def __init__(self, subsys, subscriptions):
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
        if 'handle' not in self.__dict__:
            return
        if not self.handle:
            return
        nfct_close(self.handle)

__all__ = ('ConntrackBase',)

