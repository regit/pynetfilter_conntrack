from pynetfilter_conntrack import (ConntrackEntry, nfexp_snprintf,
    NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3)
from ctypes import create_string_buffer
from pynetfilter_conntrack.conntrack_entry import BUFFER_SIZE

class ExpectEntry(ConntrackEntry):
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
        ret = nfexp_snprintf(buffer, BUFFER_SIZE, self._conntrack, msgtype, msg_output, flags)
        if ret <= 0:
            raise RuntimeError("nfexp_snprintf() failure")
        return buffer.value

__all__ = ('ExpectEntry',)

