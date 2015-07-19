from __future__ import absolute_import, division, print_function


from math import sqrt

from fractions import gcd

__all__ = ['modexp', 'gcd', 'egcd', 'modinv', 'divides', 'factors', 'isprime',
           'sqrt', 'dlog']


def modexp(base, exp, n):
    """
    Compute base**exp (mod n)
    """
    s = 1
    while exp != 0:
        if exp & 1:
            s = (s * base) % n
        exp >>= 1
        base = (base * base) % n
    return s


def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a, m):
    gcd_, x, y = egcd(a, m)
    if gcd_ != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def divides(d, n):
    """
    Answer whether int `d` is a divisor of int `n`.
    """
    if not isinstance(d, int) or d == 0:
        raise ValueError(d)
    if not isinstance(n, int) or n == 0:
        raise ValueError(n)
    return n % d == 0


def factors(n):
    """
    Answer set of factors of `n`, including 1 and `n`.
    """
    fs = set()
    for i in range(1, int(sqrt(n)) + 1):
        div, rem = divmod(n, i)
        if rem == 0:
            fs.add(i)
            fs.add(div)
    return fs


def isprime(n):
    """
    Answer whether integer n (must be greater than 1) is prime.
    """
    return len(factors(n)) == 2


def dlog(n, g, h):
    """
    Answer the discrete log of `h` in group "Z^{*}_{n}",
    that is, the x such that `xg == h` in the group, or None.
    """
    assert isprime(n)
    for i in range(1, n + 1):
        if gcd(n, i) == 1 and pow(g, i, n) == h:
            return i
    return None
