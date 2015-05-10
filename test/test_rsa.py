from __future__ import absolute_import, division, print_function

import cryptoplay.rsa as R
import cryptoplay.math as M


def test_rsa1():
    rsa = R.RSA(61, 53)
    e = 17
    d = 2753
    pk = rsa.n, e
    sk = d
    msg = 65
    ciphertext = rsa.encrypt(msg, e)
    plaintext = rsa.decrypt(ciphertext, sk)
    assert ciphertext == msg ** pk[1] % pk[0]
    assert plaintext == msg


def test_rsa2():
    rsa = R.RSA(7, 11)
    assert rsa.p == 7
    assert rsa.q == 11
    assert rsa.n == 7 * 11
    assert rsa.phi == (rsa.p - 1) * (rsa.q - 1)
    e, d = 7, 43
    assert M.gcd(e, rsa.phi) == 1
    assert e * d % rsa.phi == 1

    assert rsa.encrypt(4, e) == 60
    assert rsa.decrypt(rsa.encrypt(4, e), d) == 4

    assert rsa.sign(2, d) == 30
    assert rsa.verify(2, 30, e)
    assert not rsa.verify(2, 29, e)
