from pynetfilter_conntrack import \
    nfct_open, nfct_close
from pynetfilter_conntrack.ctypes_errno import get_errno
from os import strerror

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
            self._error('nfct_new')

    def _error(self, func_name):
        errno = get_errno()
        err_msg = strerror(errno)
        raise RuntimeError("%s() failure: %s" % (func_name, err_msg))

    def __del__(self):
        """Destroy conntrack object"""
        if 'handle' not in self.__dict__:
            return
        self.close()

    def close(self):
        if not self.handle:
            return
        nfct_close(self.handle)
        self.handle = None

__all__ = ('ConntrackBase',)

