from __future__ import absolute_import, division, print_function

import pytest

import cryptoplay.util as U


def test_split_at_empty():
    with pytest.raises(ValueError):
        U.split_at([], 0)


def test_split_at_head():
    a, b = U.split_at([1, 2], 0)
    assert a == []
    assert b == [1, 2]


def test_split_at_tail():
    a, b = U.split_at([1, 2], 2)
    assert a == [1, 2]
    assert b == []


def split_at_middle():
    lsts = [[1, 2, 3, 4], [1, 2, 3, 4, 5, 6, 7]]
    for lst in lsts:
        for i in range(len(lst)):
            a, b = U.split_at(i)
            assert a == lst[:i]
            assert b == lst[i:]
