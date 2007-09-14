from pynetfilter_conntrack import nfct_handle_p, nfct_callback_t
from pynetfilter_conntrack.func import library
from ctypes import (Structure, POINTER, CFUNCTYPE,
    c_int, c_void_p, c_char_p, c_uint)

#--------------------------------------------------------------------------
# Define nf_expect: pointer to fake structures
class nf_expect(Structure):
    pass
nf_expect_p = POINTER(nf_expect)

nfexp_callback_t = CFUNCTYPE(c_int, c_int, nf_expect_p, c_void_p)

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

__all__ = (
    'nf_expect_p', 'nfexp_callback_t',
    'nfexp_query', 'nfexp_callback_register', 'nfexp_snprintf',
    'nfexp_callback_unregister', 'nfexp_catch',
)
