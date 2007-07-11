from ctypes import string_at
import struct

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

def uint32(n):
    import sys
    if sys.hexversion < 0x2040000:
        if n < 0:
            return 0x100000000 + n
        return n
    return n & 0xFFFFFFFF
        

__all__ = ("raw2long", "ctypes_ptr2uint", "uint32")

