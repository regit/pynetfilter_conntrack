from pynetfilter_conntrack import (ConntrackEntry,
    nfexp_new, nfexp_destroy, nfexp_snprintf,
    NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3)
from ctypes import create_string_buffer
from pynetfilter_conntrack.conntrack_entry import BUFFER_SIZE

class ExpectEntry(ConntrackEntry):
    @staticmethod
    def new(expect):
        handle = nfexp_new()
        return ExpectEntry(expect, handle)

    def __del__(self):
        if '_destroy' not in self.__dict__ or not self._destroy:
            return
        if '_handle' not in self.__dict__ or not self._handle:
            return
        nfexp_destroy(self._handle)

    def format(self, msg_output=NFCT_O_DEFAULT, msgtype=None, flags=NFCT_OF_SHOW_LAYER3):
        """
        Format the entry:
         - msgtype: NFCT_T_UNKNOWN, NFCT_T_NEW, NFCT_T_UPDATE,
                    NFCT_T_DESTROY or NFCT_T_ERROR
         - msg_output: NFCT_O_DEFAULT or NFCT_O_XML
         - flags: 0 or NFCT_OF_SHOW_LAYER3

        Return a string.

        Raise a RuntimeError on error.
        """
        buffer = create_string_buffer(BUFFER_SIZE)
        if msgtype is None:
            msgtype = self._msgtype
        ret = nfexp_snprintf(buffer, BUFFER_SIZE, self._handle, msgtype, msg_output, flags)
        if ret <= 0:
            raise RuntimeError("nfexp_snprintf() failure")
        return buffer.value

__all__ = ('ExpectEntry',)
