from pynetfilter_conntrack import NFCT_Q_CREATE, NFCT_T_UNKNOWN
from pynetfilter_conntrack.ctypes_errno import get_errno
from os import strerror

BUFFER_SIZE = 1024 # bytes including nul byte

class EntryBase(object):
    def __init__(self, conntrack, handle, msgtype=NFCT_T_UNKNOWN, destroy=True, attr=None):
        if not handle:
            raise RuntimeError("Empty entry handler")
        if not attr:
            attr = {}
        object.__setattr__(self, "_attr", attr)
        object.__setattr__(self, "_destroy", destroy)
        object.__setattr__(self, "_handle", handle)
        object.__setattr__(self, "_sub_system", conntrack)
        object.__setattr__(self, "_msgtype", msgtype)

    def _error(self, func_name):
        errno = get_errno()
        err_msg = strerror(errno)
        raise RuntimeError("%s() failure: %s" % (func_name, err_msg))

    def query(self, command):
        self._sub_system.query(command, self._handle)

    def create(self):
        self.query(NFCT_Q_CREATE)

    def __str__(self):
        return self.format()

    def __del__(self):
        if '_destroy' not in self.__dict__ or not self._destroy:
            return
        if '_handle' not in self.__dict__ or not self._handle:
            return
        self._free()
        object.__setattr__(self, '_handle', None)

    # --- Abstract methods ---

    def format(self, **kw):
        raise NotImplementedError()

    def free(self):
        raise NotImplementedError()

__all__ = ('EntryBase', 'BUFFER_SIZE')

