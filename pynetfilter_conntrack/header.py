#!/usr/bin/env python
"""
Copyright(C) 2006 INL
Written by Victor Stinner <victor.stinner AT inl.fr>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 2 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
---
pynetfilter_conntrack is a Python binding of libnetfilter_conntrack:
   http://www.netfilter.org/projects/libnetfilter_conntrack/index.html
"""
from ctypes import \
    POINTER, CFUNCTYPE, cast, \
    c_char_p, c_void_p, c_int, c_uint, \
    cdll
from pynetfilter_conntrack.ctypes_stdint import uint8_t, uint32_t
from pynetfilter_conntrack.nf_struct import \
    nfct_handle_p, nfct_l4, nfct_address, nfct_tuple, nfct_protoinfo, \
    nfct_nat, nfct_counters, nfct_conntrack, nfct_conntrack_compare

# ------------------------------- Functions ---------------------------------

# Prototype of a callback. Arguments:
# - conntrack (POINTER(nfct_conntrack)):
#       Pointer to a conntrack entry. The conntrack is a static buffer,
#       so use ctypes_copy() if you would like to store it
# - flags (int):
#       See NFCT_NAMES
# - msg_type (int):
#       Message type: NFCT_MSG_NEW, NFCT_MSG_DESTROY, NFCT_MSG_UPDATE
#       or NFCT_MSG_UNKNOWN
# - data (void*):
#       User data set using nfct_register_callback()
#
# Return: have to return 0
nfct_callback = CFUNCTYPE(c_int, POINTER(nfct_conntrack), c_uint, c_int, POINTER(nfct_conntrack_compare))

# Open the dynamic library
_nfct_library = cdll.LoadLibrary("libnetfilter_conntrack.so.1")

# nfct_open(): open a netfilter handler
nfct_open = _nfct_library.nfct_open
nfct_open.argtypes = (uint8_t, c_uint)
#        nfct_open.restype = nfct_handle_p  # doesn't work!?

# nfct_close(handler): close a netfilter handler
nfct_close = _nfct_library.nfct_close
nfct_close.argtypes = [nfct_handle_p]
nfct_close.restype = c_int

# nfct_sprintf_conntrack(buffer, conntrack, flags) -> length
#    Convert a conntrack to string, see NFCT_NAMES for flags
#    Returns length of the string in bytes (doesn't count the nul byte)
nfct_sprintf_conntrack = _nfct_library.nfct_sprintf_conntrack
nfct_sprintf_conntrack.restype = c_int
nfct_sprintf_conntrack.argtypes = \
    (c_char_p, POINTER(nfct_conntrack), c_uint)

# nfct_register_callback(): setup a callback used by nfct_dump_conntrack_table()
# Convert your Python function to nfct_callback type
# WARNING: callback shouldn't be deleted before
#          nfct_register_callback(hdl, None, None) is called
#          or ctypes will crash
#
# Callback prototype is nfct_callback
nfct_register_callback = _nfct_library.nfct_register_callback
nfct_register_callback.restype = None
nfct_register_callback.argtypes = (nfct_handle_p, c_void_p, c_void_p)

# nfct_dump_conntrack_table(): walk in the connection table
# Use nfct_register_callback() to use callback for each entry
nfct_dump_conntrack_table = _nfct_library.nfct_dump_conntrack_table
nfct_dump_conntrack_table.argtypes = (nfct_handle_p, c_int)
nfct_dump_conntrack_table.restype = c_int

# nfct_get_conntrack()
#    Search a connection using its ID and/or a tuple
# Arguments:
#  - cth (nfct_handle*): NetFilter handler
#  - tuple (nfct_tuple*): A tuple used to select the connection
#  - dir (int): Direction: NFCT_DIR_ORIGINAL or NFCT_DIR_REPLY
#  - id (uint32_t): Connection identifier
# Returns an integer
# Use nfct_register_callback() to set function which will be called on each
# match
nfct_get_conntrack = _nfct_library.nfct_get_conntrack
nfct_get_conntrack.argtypes = (nfct_handle_p, POINTER(nfct_tuple), c_int, uint32_t)
nfct_get_conntrack.restype = c_int

# nfct_update_conntrack()
nfct_update_conntrack = _nfct_library.nfct_update_conntrack
nfct_update_conntrack.argtypes = (nfct_handle_p, POINTER(nfct_conntrack))
nfct_update_conntrack.restype = c_int

# nfct_delete_conntrack()
nfct_delete_conntrack = _nfct_library.nfct_delete_conntrack
nfct_delete_conntrack.argtypes = (nfct_handle_p, POINTER(nfct_tuple), c_int, uint32_t)
nfct_delete_conntrack.restype = int

