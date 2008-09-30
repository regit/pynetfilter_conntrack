from pynetfilter_conntrack import nfct_handle_p
from pynetfilter_conntrack.func import library
from ctypes import (Structure, POINTER, CFUNCTYPE,
    c_int, c_void_p, c_char_p, c_uint)
from pynetfilter_conntrack.ctypes_stdint import uint8_t, uint16_t, uint32_t

#--------------------------------------------------------------------------
# Define nf_expect: pointer to fake structures
class nf_expect(Structure):
    pass
nf_expect_p = POINTER(nf_expect)

nfexp_callback_t = CFUNCTYPE(c_int, c_int, nf_expect_p, c_void_p)

#--------------------------------------------------------------------------
# struct nf_expect *nfexp_new(void);
nfexp_new = library.nfexp_new
nfexp_new.argtypes = None
nfexp_new.restype = nf_expect_p

#--------------------------------------------------------------------------
# void nfexp_destroy(struct nf_expect *exp);
nfexp_destroy = library.nfexp_destroy
nfexp_destroy.argtypes = None
nfexp_destroy.restype = nf_expect_p

# -------------------------------------------------------------------------
# int nfexp_query(struct nfct_handle *h,
#                 const enum nf_conntrack_query qt,
#                 const void *data);
nfexp_query = library.nfexp_query
nfexp_query.argtypes = (nfct_handle_p, c_int, c_void_p)
nfexp_query.restype = c_int

#--------------------------------------------------------------------------
# int nfexp_callback_register(struct nfct_handle *h,
#                            enum nf_conntrack_msg_type type,
#                            int (*cb)(enum nf_conntrack_msg_type type,
#                                      struct nf_conntrack *ct,
#                                      void *data),
#                            void *data);
# Register callback.
nfexp_callback_register = library.nfexp_callback_register
nfexp_callback_register.argtypes = (nfct_handle_p, c_int, nfexp_callback_t, c_void_p)
nfexp_callback_register.restype = c_int

#--------------------------------------------------------------------------
# int nfexp_snprintf(char *buf,
#                    unsigned int size,
#                    const struct nf_expect *exp,
#                    const unsigned int msg_type,
#                    const unsigned int out_type,
#                    const unsigned int out_flags);
nfexp_snprintf = library.nfexp_snprintf
nfexp_snprintf.argtypes = (c_char_p, c_uint, nf_expect_p, c_uint, c_uint, c_uint)
nfexp_snprintf.restype = c_int

#--------------------------------------------------------------------------
# void nfexp_callback_unregister(struct nfct_handle *h);
nfexp_callback_unregister = library.nfexp_callback_unregister
nfexp_callback_unregister.argtypes = (nfct_handle_p,)
nfexp_callback_unregister.restype = None

# -------------------------------------------------------------------------
# int nfct_catch(struct nfct_handle *h);
nfexp_catch = library.nfexp_catch
nfexp_catch.argtypes = (nfct_handle_p,)
nfexp_catch.restype = c_int

# -------------------------------------------------------------------------
# void nfexp_set_attr(struct nf_expect *exp,
#                     const enum nf_expect_attr type,
#                     const void *value);
#
# void nfexp_set_attr_u8(struct nf_expect *exp,
#                        const enum nf_expect_attr type,
#                        u_int8_t value);
#
# void nfexp_set_attr_u16(struct nf_expect *exp,
#                         const enum nf_expect_attr type,
#                         u_int16_t value);
#
# void nfexp_set_attr_u32(struct nf_expect *exp,
#                         const enum nf_expect_attr type,
#                         u_int32_t value);
def setter(argtype, suffix):
    func = getattr(library, "nfexp_set_attr" + suffix)
    func.argtypes = (nf_expect_p, argtype)
    func.restype = None
    return func

nfexp_set_attr = setter(c_void_p, "")
nfexp_set_attr_u8 = setter(uint8_t, "_u8")
nfexp_set_attr_u16 = setter(uint16_t, "_u16")
nfexp_set_attr_u32 = setter(uint32_t, "_u32")
del setter

__all__ = (
    'nf_expect_p', 'nfexp_callback_t',
    'nfexp_new', 'nfexp_destroy',
    'nfexp_query', 'nfexp_callback_register', 'nfexp_snprintf',
    'nfexp_callback_unregister', 'nfexp_catch',
    'nfexp_set_attr',
    'nfexp_set_attr_u8', 'nfexp_set_attr_u16', 'nfexp_set_attr_u32',
)
