from __future__ import absolute_import, division, print_function

import pytest

import cryptoplay.math as M


def test_egcd():
    assert M.egcd(3, 2) == (1, 1, -1)


def test_modinv():
    assert M.modinv(42, 2017) == 1969
    assert M.modinv(3, 27) is None


def test_divides():
    assert M.divides(1, 2)
    assert not M.divides(2, 1)
    assert not M.divides(3, 4)
    assert M.divides(11, 99)
    assert M.divides(2, 2)
    with pytest.raises(ValueError):
        assert not M.divides(0, 2)


def test_factors():
    assert M.factors(1) == {1}
    assert M.factors(2) == {1, 2}
    assert M.factors(20) == {1, 2, 4, 5, 10, 20}


def test_isprime():
    assert M.isprime(2)
    assert not M.isprime(1)
    assert M.isprime(11)
    assert not M.isprime(51)
    assert M.isprime(53)


def test_dlog():
    assert M.dlog(11, 2, 1) == 10
