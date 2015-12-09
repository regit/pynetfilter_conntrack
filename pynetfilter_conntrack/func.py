from ctypes import Structure, cdll, POINTER, CFUNCTYPE,\
    c_int, c_uint, c_void_p, c_char_p, util
from pynetfilter_conntrack.ctypes_stdint import uint8_t, uint16_t, uint32_t

# Open the dynamic library
library = cdll.LoadLibrary(util.find_library("netfilter_conntrack"))

#--------------------------------------------------------------------------
# Define nf_conntrack_p and nfct_handle_p: pointer to fake structures
#
#class nf_conntrack(Structure):
#    pass
#class nfct_handle(Structure):
#    pass
#
#nf_conntrack_p = POINTER(nf_conntrack)
#nfct_handle_p = POINTER(nfct_handle)
nf_conntrack_p = c_int
nfct_handle_p = c_int

class nfct_conntrack_compare_t(Structure):
    _fields_ = (
        ("ct", nf_conntrack_p),
        ("flags", c_uint),
        ("l3flags", c_uint),
        ("l4flags", c_uint),
    )
nfct_conntrack_compare_p = POINTER(nfct_conntrack_compare_t)

#--------------------------------------------------------------------------
# int callback(enum nf_conntrack_msg_type type,
#              struct nf_conntrack *ct,
#              void *data)
#
# Callback type
nfct_callback_t = CFUNCTYPE(c_int, c_int, nf_conntrack_p, c_void_p)

#--------------------------------------------------------------------------
# struct nf_conntrack *nfct_new(void): Allocate a new conntrack
#
# In case of success, this function returns a valid pointer to a memory blob,
# otherwise NULL is returned and errno is set appropiately."""
nfct_new = library.nfct_new
nfct_new.argtypes = None
nfct_new.restype = nf_conntrack_p

#--------------------------------------------------------------------------
# void nfct_destroy(struct nf_conntrack *ct): Release a conntrack object
#
# @ct: pointer to the conntrack object
nfct_destroy = library.nfct_destroy
nfct_destroy.argtypes = (nf_conntrack_p, )
nfct_destroy.restype = None

#--------------------------------------------------------------------------
# struct nfct_handle *nfct_open(u_int8_t subsys_id, unsigned subscriptions)
#
# Open a conntrack handler
nfct_open = library.nfct_open
nfct_open.argtypes = (uint8_t, c_uint)
nfct_open.restype = nfct_handle_p

#--------------------------------------------------------------------------
# int nfct_close(struct nfct_handle *cth)
#
# Open a conntrack handler
nfct_close = library.nfct_close
nfct_close.argtypes = (nfct_handle_p,)
nfct_close.restype = c_int

#--------------------------------------------------------------------------
# int nfct_query(struct nfct_handle *h,
#                const enum nf_conntrack_query qt,
#                const void *data)
#
# Send a query to ctnetlin
#    @h: library handler
#    @qt: query type
#    @data: data required to send the query
#
# On error, -1 is returned and errno is explicitely set. On success, 0
# is returned
nfct_query = library.nfct_query
nfct_query.argtypes = (nfct_handle_p, c_int, c_void_p)
nfct_query.restype = c_int

#--------------------------------------------------------------------------
# int nfct_callback_register(struct nfct_handle *h,
#                            enum nf_conntrack_msg_type type,
#                            int (*cb)(enum nf_conntrack_msg_type type,
#                                      struct nf_conntrack *ct,
#					                   void *data),
#				             void *data);
# Register callback.
nfct_callback_register = library.nfct_callback_register
nfct_callback_register.argtypes = (nfct_handle_p, c_int, nfct_callback_t, c_void_p)
nfct_callback_register.restype = c_int

#--------------------------------------------------------------------------
# void nfct_callback_unregister(struct nfct_handle *h)
#
# Unregister callback
nfct_callback_unregister = library.nfct_callback_unregister
nfct_callback_unregister.argtypes = (nfct_handle_p,)
nfct_callback_unregister.restype = None

#--------------------------------------------------------------------------
# int nfct_snprintf(char *buf,
#                   unsigned int size,
#                   const struct nf_conntrack *ct,
#                   const unsigned int msg_type,
#                   const unsigned int out_type,
#                   const unsigned int out_flags);
#
# Format a conntrack entry to a string
nfct_snprintf = library.nfct_snprintf
nfct_snprintf.argtypes = (c_char_p, c_uint, nf_conntrack_p, c_uint, c_uint, c_uint)
nfct_snprintf.restype = c_int

#--------------------------------------------------------------------------
# struct nf_conntrack *nfct_clone(const struct nf_conntrack *ct)
# nfct_clone - clone a conntrack object
# @ct: pointer to a valid conntrack object
#
# On error, NULL is returned and errno is appropiately set. Otherwise,
# a valid pointer to the clone conntrack is returned.
nfct_clone = library.nfct_clone
nfct_clone.argtypes = (nf_conntrack_p,)
nfct_clone.restype = nf_conntrack_p

#--------------------------------------------------------------------------
# const void *nfct_get_attr(const struct nf_conntrack *ct,
#				 const enum nf_conntrack_attr type);
# u_int8_t nfct_get_attr_u8(const struct nf_conntrack *ct,
#				 const enum nf_conntrack_attr type);
# u_int16_t nfct_get_attr_u16(const struct nf_conntrack *ct,
#				   const enum nf_conntrack_attr type);
# u_int32_t nfct_get_attr_u32(const struct nf_conntrack *ct,
#				   const enum nf_conntrack_attr type);
#
# Get an attribute on a conntrack entry
def getter(restype, suffix):
    func = getattr(library, "nfct_get_attr" + suffix)
    func.argtypes = (nf_conntrack_p, c_uint)
    func.restype = restype
    return func

nfct_get_attr = getter(c_void_p, "")
nfct_get_attr_u8 = getter(uint8_t, "_u8")
nfct_get_attr_u16 = getter(uint16_t, "_u16")
nfct_get_attr_u32 = getter(uint32_t, "_u32")
del getter


#--------------------------------------------------------------------------
# void nfct_set_attr(struct nf_conntrack *ct,
#                    const enum nf_conntrack_attr type,
#                    void *value);
#
# void nfct_set_attr_u8(struct nf_conntrack *ct,
#                       const enum nf_conntrack_attr type,
#                       u_int8_t value);
#
# void nfct_set_attr_u16(struct nf_conntrack *ct,
#                        const enum nf_conntrack_attr type,
#                        u_int16_t value);
#
# void nfct_set_attr_u32(struct nf_conntrack *ct,
#                        const enum nf_conntrack_attr type,
#                        u_int32_t value);
#
# Set an attribute on a conntrack entry
def setter(argtype, suffix):
    func = getattr(library, "nfct_set_attr" + suffix)
    func.argtypes = (nf_conntrack_p, argtype)
    func.restype = None
    return func

nfct_set_attr = setter(c_void_p, "")
nfct_set_attr_u8 = setter(uint8_t, "_u8")
nfct_set_attr_u16 = setter(uint16_t, "_u16")
nfct_set_attr_u32 = setter(uint32_t, "_u32")
del setter

# -------------------------------------------------------------------------
# int nfct_catch(struct nfct_handle *h);
nfct_catch = library.nfct_catch
nfct_catch.argtypes = (nfct_handle_p,)
nfct_catch.restype = c_int

# -------------------------------------------------------------------------
# int nfct_setobjopt(struct nf_conntrack *ct, unsigned int option);
nfct_setobjopt = library.nfct_setobjopt
nfct_setobjopt.argtypes = (nf_conntrack_p, c_uint)
nfct_setobjopt.restype = c_int

# -------------------------------------------------------------------------
# int nfct_conntrack_compare(struct nfct_conntrack *ct1,
#                            struct nfct_conntrack *ct2,
#                            struct nfct_conntrack_compare *cmp);
nfct_conntrack_compare = library.nfct_cmp
nfct_conntrack_compare.argtypes = (nf_conntrack_p, nf_conntrack_p, nfct_conntrack_compare_p)
nfct_conntrack_compare.restype = c_int

# -------------------------------------------------------------------------

__all__ = (
    "nfct_handle_p", "nfct_callback_t",
    "nfct_new", "nfct_destroy", "nfct_open", "nfct_close", "nfct_query",
    "nfct_callback_register", "nfct_callback_unregister",
    "nfct_clone", "nfct_snprintf", "nfct_catch", "nfct_setobjopt",
    "nfct_get_attr", "nfct_get_attr_u8", "nfct_get_attr_u16", "nfct_get_attr_u32",
    "nfct_set_attr", "nfct_set_attr_u8", "nfct_set_attr_u16", "nfct_set_attr_u32",
    "nfct_conntrack_compare_t", "nfct_conntrack_compare",
)

