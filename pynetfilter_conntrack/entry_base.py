from pynetfilter_conntrack import NFCT_Q_CREATE, NFCT_T_UNKNOWN

class EntryBase(object):
    def __init__(self, conntrack, handle, msgtype=NFCT_T_UNKNOWN, destroy=True):
        self._destroy = destroy
        self._handle = handle
        self._sub_system = conntrack
        if not self._handle:
            raise RuntimeError("Empty entry handler")
        self._msgtype = msgtype
        self._attr = {}

    def query(self, command):
        self._sub_system.query(command, self._handle)

    def create(self):
        self.query(NFCT_Q_CREATE)

    def __str__(self):
        return self.format()

    # --- Abstract methods ---

    def format(self, **kw):
        raise NotImplementedError()

