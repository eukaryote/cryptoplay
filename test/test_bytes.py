from __future__ import absolute_import, division, print_function

import pytest

import cryptoplay.bytes as B


def test_byte_to_bin_ints():
    assert B.byte_to_bin(0) == '0' * 8
    assert B.byte_to_bin(1) == '0' * 7 + '1'
    assert B.byte_to_bin(15) == '0' * 4 + '1' * 4
    with pytest.raises(ValueError):
        B.byte_to_bin(-1)
    with pytest.raises(ValueError):
        B.byte_to_bin(2.0)


def test_ascii_to_hex_onechar():
    assert B.ascii_to_hex(' ') == '20'


def test_ascii_to_hex_multichar():
    t = [hex(c)[2:] for c in map(ord, 'fgh')]
    assert B.ascii_to_hex('fgh') == ''.join(t)


def test_ascii_to_int_one_char():
    assert B.ascii_to_int(' ') == 32


def test_ascii_to_int_multichar():
    s = hex(ord('A'))[2:] + hex(ord('F'))[2:]
    assert B.ascii_to_int('AF') == int(s, 16)


def test_ascii_to_bin_one_char():
    b = '00100000'
    assert int(b, 2) == 32
    assert B.ascii_to_bin(' ') == b


def test_ascii_to_bin_multichar():
    b1, b2 = '00100000', '01100001'
    assert int(b1, 2) == 32 and ord(' ') == 32
    assert int(b2, 2) == 97 and ord('a') == 97
    assert B.ascii_to_bin(' a') == b1 + b2


def test_int_to_byte_ints():
    assert B.int_to_byte_ints(3) == [3]
    assert B.int_to_byte_ints(19958181) == [1, 48, 137, 165]


def test_to_byte_ints():
    assert B.to_byte_ints(3) == [3]
    assert B.to_byte_ints('13089a5') == [1, 48, 137, 165]


def test_xor_ints():
    assert B.xor_(3, 4) == 3 ^ 4


def test_xor_bytes():
    assert B.xor_(chr(3), chr(4)) == chr(3 ^ 4)


def test_xor_same_size():
    assert B.xor_([1, 2], [3, 4]) == [1 ^ 3, 2 ^ 4]


def test_xor_first_smaller():
    assert B.xor_([1], [3, 4]) == [1 ^ 3, 4]
    assert B.xor_([1, 2], [3, 4, 5, 6]) == [1 ^ 3, 2 ^ 4, 5, 6]


def test_xor_first_larger():
    assert B.xor_([1, 1, 3, 4], [3]) == [1 ^ 3, 1, 3, 4]
    assert B.xor_([1, 2, 3, 4, 5, 6], [1, 2, 3]) == [0, 0, 0, 4, 5, 6]


def test_and_ints():
    assert B.and_(3, 2) == 3 & 2 == 2


def test_and_bytes():
    assert B.and_(' ', 'a') == ord(' ') & ord('a')


def test_and_int_list():
    assert B.and_([1, 2], [3, 4]) == [1 & 3, 2 & 4]


def test_and_byte_list():
    assert B.and_([' ', 'a'], ['c', 'd']) == [ord(' ') & ord('c'),
                                              ord('a') & ord('d')]


def test_and_lists():
    assert B.and_([1, 2, 3], [4]) == [1 & 4, 0, 0]
