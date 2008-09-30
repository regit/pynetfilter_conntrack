from pynetfilter_conntrack import \
    nfct_new, nfct_destroy, nfct_snprintf,\
    nfct_get_attr, nfct_get_attr_u8, nfct_get_attr_u16, nfct_get_attr_u32,\
    nfct_set_attr, nfct_set_attr_u8, nfct_set_attr_u16, nfct_set_attr_u32,\
    nfct_setobjopt,\
    NFCT_O_DEFAULT, NFCT_OF_SHOW_LAYER3,\
    ATTRIBUTES, NFCT_Q_UPDATE, \
    NFCT_Q_DESTROY, NFCT_MARK, \
    nfct_conntrack_compare_t, nfct_conntrack_compare,\
    ctypes_ptr2uint, int16_to_uint16, int32_to_uint32
from ctypes import create_string_buffer
from socket import ntohs, ntohl, htons, htonl
from IPy import IP
from pynetfilter_conntrack.entry_base import EntryBase, BUFFER_SIZE

IP_ATTRIBUTES = set((
    "orig_ipv4_src", "orig_ipv4_dst",
    "repl_ipv4_src", "repl_ipv4_dst",
    "orig_ipv6_src", "orig_ipv6_dst",
    "repl_ipv6_src", "repl_ipv6_dst",
))

GETTER = {
      8: nfct_get_attr_u8,
     16: nfct_get_attr_u16,
     32: nfct_get_attr_u32,
     64: nfct_get_attr,
    128: nfct_get_attr,
}
SETTER = {
      8: nfct_set_attr_u8,
     16: nfct_set_attr_u16,
     32: nfct_set_attr_u32,
     64: nfct_set_attr,
    128: nfct_set_attr,
}

HTON = {8: None, 16: htons, 32: htonl, 64: None, 128: None}

class ConntrackEntry(EntryBase):
    @staticmethod
    def new(conntrack):
        handle = nfct_new()
        return ConntrackEntry(conntrack, handle)

    def __getattr__(self, name):
        if name not in self._attr:
            self._attr[name] = self._getAttr(name)
        return self._attr[name]

    def _getAttr(self, name):
        try:
            attrid, nbits = ATTRIBUTES[name]
            getter = GETTER[nbits]
        except KeyError:
            raise AttributeError("ConntrackEntry object has no attribute '%s'" % name)
        value = getter(self._handle, attrid)
        if 32 < nbits:
            return ctypes_ptr2uint(value, nbits//8)

        if nbits in (16, 32) and name not in ("mark", "timeout", "status"):
            if nbits == 16:
                value = ntohs(value)
                value = int16_to_uint16(value)
            else:
                value = ntohl(value)
                value = int32_to_uint32(value)
        if name in IP_ATTRIBUTES:
            value = IP(value, ipversion=4)
        return value

    def _setAttr(self, name, value):
        try:
            attrid, nbits = ATTRIBUTES[name]
            setter = SETTER[nbits]
            hton = HTON[nbits]
        except KeyError:
            raise AttributeError("ConntrackEntry object has no attribute '%s'" % name)
        if hton and name not in ("mark", "timeout", "status"):
            value = hton(value)
        setter(self._handle, attrid, value)
        return value

    def __setattr__(self, name, value):
        if name in ATTRIBUTES:
            python_value = value
            if name in IP_ATTRIBUTES:
                if isinstance(value, IP):
                    value = value.int()
                else:
                    python_value = IP(value, ipversion=4)
            self._attr[name] = python_value
            self._setAttr(name, value)
        elif name.startswith('_'):
            object.__setattr__(self, name, value)
        else:
            raise AttributeError("ConntrackEntry object has no attribute '%s'" % name)

    def _free(self):
        """
        Destroy the conntrack entry: free the memory.
        Function called by the Python destructor.
        """
        nfct_destroy(self._handle)

    def destroy(self):
        """
        Destroy (kill) a connection in the conntrack table.
        """
        self.query(NFCT_Q_DESTROY)

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
        ret = nfct_snprintf(buffer, BUFFER_SIZE, self._handle, msgtype, msg_output, flags)
        if not(0 <= ret <= (BUFFER_SIZE-1)):
            self._error('nfct_snprintf')
        return buffer.value

    def update(self):
        self.query(NFCT_Q_UPDATE)

    def setobjopt(self, option):
        nfct_setobjopt(self._handle, option)

    def compare(self, other, use_layer3=True, use_layer4=True, use_mark=False):
        flags = 0
        if use_mark:
            flags |= NFCT_MARK
        cmp_struct = nfct_conntrack_compare_t(
            None, flags, int(use_layer3), int(use_layer4))
        return nfct_conntrack_compare(self._handle, other._handle, cmp_struct)

    def __eq__(self, other):
        return self.compare(other) == 0

__all__ = ("ConntrackEntry",)

