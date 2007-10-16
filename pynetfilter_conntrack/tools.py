from ctypes import string_at
from struct import pack, unpack
from sys import hexversion

def isBigEndian():
    """
    Get machine endian: True for big endian, False for little endian
    """
    native_value = 0x1234   # 16-bit value
    native_str = pack("@H", native_value)
    bigendian_value = unpack(">H", native_str)[0]
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
    >>> raw2long("\xff\x14\x2a\x10", True) == 0xff142a10L
    True
    >>> raw2long("\x00\x01\x02\x03", False) == 0x3020100
    True
    >>> raw2long("\xff\x14\x2a\x10\xab\x00\xd9\x0e", True) == 0xff142a10ab00d90eL
    True
    >>> raw2long("\xff\xff\xff\xff\xff\xff\xff\xfe", True) == (2**64-2)
    True
    """
    assert 1 <= len(data) <= 16   # arbitrary limit: 8..128 bits
    if big_endian:
        INDEXES = xrange(len(data)-1,-1,-1)
    else:
        INDEXES = xrange(len(data))
    shift = 0L
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

def __int16_to_uint16_old(n):
    if n < 0:
        return 0x10000 + n
    else:
        return n

def __int32_to_uint32_old(n):
    if n < 0:
        return 0x100000000L + n
    else:
        return long(n)

def __int16_to_uint16_new(n):
    return n & 0xFFFF

def __int32_to_uint32_new(n):
    return n & 0xFFFFFFFFL

if hexversion < 0x2040000:
    int16_to_uint16 = __int16_to_uint16_old
    int32_to_uint32 = __int32_to_uint32_old
else:
    int16_to_uint16 = __int16_to_uint16_new
    int32_to_uint32 = __int32_to_uint32_new

int16_to_uint16.__doc__ = """Convert a 16 bits signed integer to unsigned integer.
Examples:

>>> int16_to_uint16(10627)
10627
>>> int16_to_uint16(-10627)
54909
"""

int32_to_uint32.__doc__ = """Convert a 32 bits signed integer to unsigned integer.
Examples:

>>> int32_to_uint32(1062723156)
1062723156L
>>> int32_to_uint32(-1062723156)
3232244140L
"""

__all__ = ("raw2long", "ctypes_ptr2uint", "int16_to_uint16", "int32_to_uint32")

