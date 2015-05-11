from __future__ import absolute_import, division, print_function


def split_at(elems, n=None):
    if not elems:
        raise ValueError('non-empty iterable required')
    if n is None:
        n = len(elems) // 2
    if n < 0:
        raise ValueError('invalid n: %s' % n)
    return elems[:n], elems[n:]
