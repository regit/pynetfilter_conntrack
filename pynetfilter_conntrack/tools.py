def ctypes_copy(value):
    """
    Ugly code to copy a ctypes object: create an array of one element,
    assign first entry, and returns this entry. ctypes does a copy to
    assign array entry, so we get a copy...
    """
    array = (type(value)*1)()
    array[0] = value
    copy = array[0]
    return copy

def reverse_dict(d):
    """
    Exchange dictionnary key and value

    >>> d=dict(one=1, two=2)
    >>> print d
    {'two': 2, 'one': 1}
    >>> reverse_dict(d)
    {1: 'one', 2: 'two'}
    """
    r = dict()
    for key, value in d.iteritems():
        r[value] = key
    return r

def humanDuration(second):
    """
    Convert a duration in second to human natural representation.
    Returns a string.

    >>> humanDuration(640)
    '10 min 40 sec'
    >>> humanDuration(431987)
    '4 day 23 hour 59 min 47 sec'
    """
    if not second:
        return "0 sec"
    minute, second = divmod(second, 60)
    hour, minute = divmod(minute, 60)
    day, hour = divmod(hour, 24)
    text = []
    if day:
        text.append("%u day" % day)
    if hour:
        text.append("%u hour" % hour)
    if minute:
        text.append("%u min" % minute)
    if second :
        text.append("%u sec" % second)
    return " ".join(text)

__all__ = ("ctypes_copy", "reverse_dict", "humanDuration")
