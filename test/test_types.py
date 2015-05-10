from __future__ import absolute_import, division, print_function

import cryptoplay.types as T


def test_bag():
    b = T.Bag(a=1, b=2, c=3)
    assert (b.a, b.b, b.c) == (1, 2, 3)
    assert str(b) == str(b.__dict__)
    assert repr(b) == repr(b.__dict__)


def test_bytes_init():
    assert T.Bytes().bs == []


def test_bytes_init_byte():
    assert T.Bytes('Z').bs == [ord('Z')]


def test_bytes_init_bytelist():
    assert T.Bytes([' ', 'z']).bs == map(ord, ' z')


def test_bytes_init_intsmall():
    assert T.Bytes(42).bs == [42]


def test_bytes_init_intlarge():
    assert T.Bytes(2 ** 8 + 2 ** 7).bs == [1, 2 ** 7]


def test_bytes_init_intsmalllist():
    assert T.Bytes([1, 2]).bs == [1, 2]


def test_bytes_init_intlargelist():
    # TODO: this doesn't really make sense, so shouldn't be allowed
    assert T.Bytes([257, 261]).bs == [1, 1, 1, 5]


def test_bytes():
    bs = T.Bytes([1, 2, 3])
    assert bs.bin() == ['00000001', '00000010', '00000011']
    assert bs.hex() == ['01', '02', '03']
    bs = T.Bytes([32, 97])
    assert bs.bin() == ['00100000', '01100001']
    assert bs.hex() == ['20', '61']


def test_append_ints():
    bs = T.Bytes()
    assert bs.bs == []
    res = bs.append([1, 2])
    assert res is bs
    assert bs.bs == [1, 2]
    bs.append([3, 4]).append([5, 6])
    assert bs.bs == [1, 2, 3, 4, 5, 6]


def test_append_bytes():
    bs = T.Bytes()
    assert bs.bs == []
    res = bs.append([' ', 'Z'])
    assert res is bs
    assert bs.bs == [ord(' '), ord('Z')]
