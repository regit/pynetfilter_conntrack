from pynetfilter_conntrack import nfct_destroy, nfct_snprintf,\
    nfct_get_attr, nfct_get_attr_u8, nfct_get_attr_u16, nfct_get_attr_u32,\
    nfct_set_attr, nfct_set_attr_u8, nfct_set_attr_u16, nfct_set_attr_u32,\
    NFCT_O_DEFAULT, NFCT_O_XML, NFCT_OF_SHOW_LAYER3, NFCT_T_UNKNOWN,\
    ATTRIBUTES, NFCT_Q_UPDATE, PF_INET, PF_INET6,\
    ctypes_ptr2uint, uint32
from ctypes import create_string_buffer
from socket import ntohs, ntohl, htons, htonl

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
    def __init__(self, parent, conntrack, msgtype=NFCT_T_UNKNOWN):
        """
        Create a conntrack entry.

        Raise a RuntimeError on error.
        """
        self.parent = parent
        self.conntrack = conntrack
        if not self.conntrack:
            raise RuntimeError("Unable to clone conntrack entry (no more memory?)!")
        self.msgtype = msgtype
        self.attr = {}

    def __getattr__(self, name):
        if name == "hashtuple":
            if self.orig_l3proto == PF_INET:
                ip_src = self.orig_ipv4_src
            elif self.orig_l3proto == PF_INET6:
                ip_src = self.orig_ipv6_src
            return (self.orig_l3proto,
                    ip_src,
                    self.orig_l4proto,
                    self.orig_port_src,)
        if name not in self.attr:
            self.attr[name] = self._getAttr(name)
        return self.attr[name]

    def _getAttr(self, name):
        #print "get attribute %s" % name
        try:
            attrid, nbits = ATTRIBUTES[name]
            getter = GETTER[nbits]
            ntoh = NTOH[nbits]
        except KeyError:
            raise AttributeError("ConntrackEntry object has no attribute '%s'" % name)
        value = getter(self.conntrack, attrid)
        if 32 < nbits:
            return ctypes_ptr2uint(value, nbits//8)
        if ntoh and name not in ("mark", "timeout", "status"):
            return int32_to_uint32(ntoh(value))
        else:
            return int32_to_uint32(value)

    def _setAttr(self, name, value):
        try:
            attrid, nbits = ATTRIBUTES[name]
            setter = SETTER[nbits]
            hton = HTON[nbits]
        except KeyError:
            raise AttributeError("ConntrackEntry object has no attribute '%s'" % name)
        if hton and name not in ("mark", "timeout", "status"):
            value = hton(value)
        setter(self.conntrack, attrid, value)
        return value

    def __setattr__(self, name, value):
        if name in ATTRIBUTES:
            self.attr[name] = value
            self._setAttr(name, value)
        elif name in ("parent", "conntrack", "msgtype", "attr"):
            object.__setattr__(self, name, value)
        else:
            raise AttributeError("ConntrackEntry object has no attribute '%s'" % name)

    def __del__(self):
        if self.conntrack:
            nfct_destroy(self.conntrack)

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
            msgtype = self.msgtype
        ret = nfct_snprintf(buffer, BUFFER_SIZE, self.conntrack, msgtype, msg_output, flags)
        if ret <= 0:
            raise RuntimeError("nfct_snprintf() failure")
        return buffer.value

    def update(self):
        self.parent.query(NFCT_Q_UPDATE, self.conntrack)

    def __str__(self):
        return self.format(NFCT_O_DEFAULT)

__all__ = ("ConntrackEntry",)

