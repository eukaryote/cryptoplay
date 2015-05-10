from __future__ import absolute_import, division, print_function


def byte_to_bin(b):
    if isinstance(b, str):
        b = ord(b)
    if not isinstance(b, int) or not (0 <= b <= 256):
        raise ValueError(b)
    return "{0:08b}".format(b)


def ascii_to_hex(text):
    return ''.join(hex(ord(c))[2:] for c in text)


def ascii_to_int(text):
    return int(ascii_to_hex(text), 16)


def ascii_to_bin(text):
    return ''.join(byte_to_bin(c) for c in text)


def int_to_byte_ints(n):
    if not isinstance(n, int) or n < 0:
        raise ValueError(n)
    bs = []
    while n > 0:
        n, rem = divmod(n, 256)
        bs.append(rem)
    bs.reverse()
    return bs


def to_byte_ints(x):
    """
    Convert `x` to a list of byte ints (each an int `i` such that
    0 <= i < 256).

    If `x` is an int, then it may be an arbitrarily large non-negative
    integer, and the result will be the number represented as a list of bytes.

    If `x` is a string, it will be interpreted as a base 2, 8, 16, or 64
    representation (first that succeeds) of an integer, and converted to
    an integer and then returned as a list of ints.

    If `x` has an `__iter__` method, then `to_bytes` will be called recursively
    on the elements of `x` and the results joined as a single list.
    """
    # TODO: how to deal with unfortunate ambiguity between something like
    # 'a' == 0x10 and 'a' == ord('a')?
    # Is there something better than adding a param like `ascii=False`?
    # Maybe this should be split into multiple methods?
    if isinstance(x, str):
        for base in [2, 8, 16, 64]:
            try:
                n = int(x, base)
                return int_to_byte_ints(n)
            except ValueError:
                pass
        return map(ord, x)  # non-number string
    if isinstance(x, int):
        return int_to_byte_ints(x)
    if hasattr(x, '__iter__'):
        return [elem
                for elems in x
                for elem in to_byte_ints(elems)]
    raise ValueError("unexpected input: %r" % (x,))


def xor_(x, y):
    """
    Compute the bitwise XOR of `x` and `y`, which may be both an int (in
    range 0 <= i < 256), both a byte, or both a list of those.
    """
    if type(x) != type(y):
        raise ValueError()
    if isinstance(x, (list, tuple)):
        xlen, ylen = len(x), len(y)
        res = [xor_(xx, yy) for xx, yy in zip(x, y)]
        if xlen < ylen:
            res += y[ylen - xlen:]
        elif ylen < xlen:
            res += x[ylen - xlen:]
        return res
    asstring = False
    if isinstance(x, str):
        x = ord(x)
        y = ord(y)
        asstring = True
    result = x ^ y
    if asstring:
        result = chr(result)
    return result


def and_(x, y):
    """
    Compute the bitwise AND of `x` and `y`, which may be both an int (in
    range 0 <= i < 256), both a byte, or both a list of those.
    """
    assert type(x) == type(y)
    if isinstance(x, (list, tuple)):
        xlen, ylen = len(x), len(y)
        res = [and_(xx, yy) for xx, yy in zip(x, y)]
        if xlen < ylen:
            res.extend([0] * (ylen - xlen))
        elif ylen < xlen:
            res.extend([0] * (xlen - ylen))
        return res
    if isinstance(x, str):
        x, y = ord(x), ord(y)
    return x & y
