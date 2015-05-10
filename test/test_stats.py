from __future__ import absolute_import, division, print_function

import cryptoplay.math as M
import cryptoplay.stats as S


def test_bincount():
    assert S.bincount(3, 1) == 2
    assert S.bincount(3, 0) == 6
    assert S.bincount('3', 1) == 4
    assert S.bincount('3', 0) == 4


def test_count_zeros_ones():
    assert S.count_zeros_ones(1) == (7, 1)
    assert S.count_zeros_ones([1, 2]) == (14, 2)


def test_compare_zeros_ones():
    assert S.compare_zeros_ones([1, 2, 3]) == (20, 4, 16, 10 * M.sqrt(3))
