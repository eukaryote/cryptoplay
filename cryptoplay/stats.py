from __future__ import absolute_import, division, print_function

import cryptoplay.bytes as B
import cryptoplay.math as M


def bincount(b, n):
    """
    Count the number of bits in `b` (an int or byte) that have the value `n`,
    which must be 0 or 1.
    """
    if isinstance(b, (list, tuple)):
        return [bincount(e) for e in b]
    return B.byte_to_bin(b).count(str(n))


def count_zeros_ones(b):
    """
    Count the number of zero bits and 1 bits in the int or byte `b`, returning
    the counts as a pair of ints consisting of (#zeros, #ones).
    """
    if isinstance(b, (list, tuple)):
        res = map(count_zeros_ones, b)
        return sum(r[0] for r in res), sum(r[1] for r in res)
    zeros = bincount(b, 0)
    return zeros, 8 - zeros


def compare_zeros_ones(bs):
    """
    For the given iterable of bytes or integers, tally the number of
    0 bits and the number of 1 bits, returning a 4-tuple consisting of
    (#zeros, #ones, diff, expected_diff_if_random).
    """
    zeros = ones = 0
    for b in bs:
        z = bincount(b, 0)
        zeros += z
        ones += (8 - z)
    diff = abs(zeros - ones)
    return zeros, ones, diff, 10 * M.sqrt(len(bs))

# some random tests:
# 1. A(x)=1 iff |#0(x) - #1(x)| <= 10 * sqrt(n)
#    The difference between the number of zeros and ones is less than bound
# 2. A(x)=1 iff |#oo(x) - n/4|  <= 10 * sqrt(n)
#    The number of '00' blocks should be about n/4
# 3. A(x) = 1 iff max-run-of-0(x) in long string (should be about log2(n)) is
#    less than or equal to 10 * log2(n)
