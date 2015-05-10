from __future__ import absolute_import, division, print_function

from cryptoplay.math import isprime, gcd
from cryptoplay.types import Bag
from cryptoplay.compat import range


class RSA(object):

    def __init__(self, p, q):
        assert isprime(p)
        assert isprime(q)
        assert p != q
        self.p = p
        self.q = q
        self.phi = (p - 1) * (q - 1)
        self.n = p * q
        self.z = [i for i in range(1, self.n) if gcd(i, self.n) == 1]

    def sign(self, msg, d):
        assert isinstance(msg, int)
        assert msg >= 1 and msg <= self.n
        return msg ** d % self.n

    def encrypt(self, msg, e):
        return msg ** e % self.n

    def decrypt(self, c, d):
        return c ** d % self.n

    def verify(self, msg, sig, e):
        return (sig ** e % self.n) == msg

    def iter_e(self):
        """
        Generator over all suitable ints `e` for this RSA instance.
        """
        for e in range(2, self.phi):
            if gcd(e, self.phi) == 1:
                yield e

    def inverse(self, e):
        """
        Get multiplicative inverse of int e satisfying `d * e mod phi == 1`.
        """
        # TODO: use Euclidean algo to do this more efficiently
        for d in range(2, self.n):
            if d != e and e * d % self.phi == 1:
                return d


def rsa_example():
    p, q, N = 7, 11, 7 * 11
    phi = (p - 1) * (q - 1)
    e, d = 7, 43
    assert gcd(e, phi) == 1
    assert e * d % 60 == 1
    z = [i for i in range(1, N) if gcd(i, N) == 1]

    def enc(m):
        assert m in z
        return m ** e % N

    def dec(c):
        return c ** d % N

    def sign(m):
        assert m in z
        return m ** d % N

    def verify(m, sig):
        assert m in z
        assert sig in z
        res = sig ** e % N
        if res != m:
            print('m=%s, sig=%s, res=%s' % (m, sig, res))
        return res == m

    return Bag(**locals())
