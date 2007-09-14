from pynetfilter_conntrack import \
    nfct_new, nfct_destroy, nfct_snprintf,\
    nfct_get_attr, nfct_get_attr_u8, nfct_get_attr_u16, nfct_get_attr_u32,\
    nfct_set_attr, nfct_set_attr_u8, nfct_set_attr_u16, nfct_set_attr_u32,\
    nfct_setobjopt,\
    NFCT_O_DEFAULT, NFCT_O_XML, NFCT_OF_SHOW_LAYER3, NFCT_T_UNKNOWN,\
    ATTRIBUTES, NFCT_Q_UPDATE, PF_INET, PF_INET6,\
    NFCT_Q_CREATE, NFCT_Q_DESTROY,\
    ctypes_ptr2uint, int32_to_uint32
from ctypes import create_string_buffer
from socket import ntohs, ntohl, htons, htonl
from IPy import IP

IPV4_ATTRIBUTES = set(("orig_ipv4_src", "orig_ipv4_dst",
    "repl_ipv4_src", "repl_ipv4_dst"))

BUFFER_SIZE = 1024 # bytes including nul byte

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

NTOH = {8: None, 16: ntohs, 32: ntohl, 64: None, 128: None}
HTON = {8: None, 16: htons, 32: htonl, 64: None, 128: None}

class ConntrackEntry(object):
    @staticmethod
    def new(conntrack):
        handle = nfct_new()
        return ConntrackEntry(conntrack, handle)

    def __init__(self, conntrack, handle, msgtype=NFCT_T_UNKNOWN, destroy=True):
        """
        Create a conntrack entry.

        Raise a RuntimeError on error.
        """
        self._destroy = destroy
        self._handle = handle
        self._conntrack = conntrack
        if not self._handle:
            raise RuntimeError("Unable to clone conntrack entry (no more memory?)!")
        self._msgtype = msgtype
        self._attr = {}

    def __getattr__(self, name):
        if name not in self._attr:
            self._attr[name] = self._getAttr(name)
        return self._attr[name]

    def _getAttr(self, name):
        #print "get attribute %s" % name
        try:
            attrid, nbits = ATTRIBUTES[name]
            getter = GETTER[nbits]
            ntoh = NTOH[nbits]
        except KeyError:
            raise AttributeError("ConntrackEntry object has no attribute '%s'" % name)
        value = getter(self._handle, attrid)
        if 32 < nbits:
            return ctypes_ptr2uint(value, nbits//8)
        if ntoh and name not in ("mark", "timeout", "status"):
            value = ntoh(value)
        value = int32_to_uint32(value)
        if name in IPV4_ATTRIBUTES:
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
            if name in IPV4_ATTRIBUTES:
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

    def __del__(self):
        if '_destroy' not in self.__dict__ or not self._destroy:
            return
        if '_handle' not in self.__dict__ or not self._handle:
            return
        nfct_destroy(self._handle)

    def destroy(self):
        """
        Destroy (kill) a connection in the conntrack table.
        """
        self._conntrack.query(NFCT_Q_DESTROY, self._handle)

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
        if ret <= 0:
            raise RuntimeError("nfct_snprintf() failure")
        return buffer.value

    def _query(self, command):
        self._conntrack.query(command, self._handle)

    def update(self):
        self._query(NFCT_Q_UPDATE)

    def create(self):
        self._query(NFCT_Q_CREATE)

    def __str__(self):
        return self.format(NFCT_O_DEFAULT)

    def setobjopt(self, option):
        nfct_setobjopt(self._handle, option)

__all__ = ("ConntrackEntry",)

