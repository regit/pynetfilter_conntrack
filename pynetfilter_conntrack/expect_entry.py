from pynetfilter_conntrack import \
    nfexp_new, nfexp_destroy, nfexp_snprintf,\
    NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3
from ctypes import create_string_buffer
from pynetfilter_conntrack.entry_base import EntryBase, BUFFER_SIZE

class ExpectEntry(EntryBase):
    @staticmethod
    def new(expect):
        handle = nfexp_new()
        return ExpectEntry(expect, handle)

    def _free(self):
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
        if not(0 <= ret <= (BUFFER_SIZE-1)):
            self._error('nfct_snprintf')
        return buffer.value

__all__ = ('ExpectEntry',)

