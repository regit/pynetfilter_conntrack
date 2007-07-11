from ctypes import string_at
import struct, sys

def isBigEndian():
    """
    Get machine endian: True for big endian, False for little endian
    """
    native_value = 0x1234   # 16-bit value
    native_str = struct.pack("@H", native_value)
    bigendian_value = struct.unpack(">H", native_str)[0]
    return (bigendian_value == native_value)

def raw2long(data, big_endian):
    r"""
    Convert a raw data (type 'str') into a long integer.

    >>> chr(raw2long('*', True))
    '*'
    >>> raw2long("\x00\x01\x02\x03", True) == 0x10203
    True
    >>> raw2long("\x2a\x10", False) == 0x102a
    True
    >>> raw2long("\xff\x14\x2a\x10", True) == 0xff142a10
    True
    >>> raw2long("\x00\x01\x02\x03", False) == 0x3020100
    True
    >>> raw2long("\xff\x14\x2a\x10\xab\x00\xd9\x0e", True) == 0xff142a10ab00d90e
    True
    >>> raw2long("\xff\xff\xff\xff\xff\xff\xff\xfe", True) == (2**64-2)
    True
    """
    assert 1 <= len(data) <= 16   # arbitrary limit: 8..128 bits
    if big_endian:
        INDEXES = xrange(len(data)-1,-1,-1)
    else:
        INDEXES = xrange(len(data))
    shift = 0
    value = 0
    for index in INDEXES:
        byte = ord(data[index])
        value += (byte << shift)
        shift += 8
    return value

def ctypes_ptr2uint(ptr, size):
    """
    Read unsigned integer of 'size' bytes at 'ptr' address where 'ptr' is
    a ctypes 'c_void_p' pointer. Use machine endian.
    """
    raw = string_at(ptr, size)
    return raw2long(raw, ctypes_ptr2uint.big_endian)
ctypes_ptr2uint.big_endian = isBigEndian()

def __int32_to_uint32_old(n):
    """
    Convert a signed integer to unsigned integer for python version lesser than 2.4.
    """
    if n < 0:
        return 0x100000000 + n
    return n

def __int32_to_uint32_new(n):
    """
    Convert a signed integer to unsigned integer for python version greater or equal to 2.4.
    """
    return n & 0xFFFFFFFF

if sys.hexversion < 0x2040000:
    int32_to_uint32 = __int32_to_uint32_old
else:
    int32_to_uint32 = __int32_to_uint32_new
int32_to_uint32.__doc__ = """Convert a signed integer to unsigned integer.
Examples:

>>> int32_to_uint32(-1062723156)
3232244140L

>>> int32_to_uint32(1062723156)
1062723156
"""

__all__ = ("raw2long", "ctypes_ptr2uint", "int32_to_uint32")

