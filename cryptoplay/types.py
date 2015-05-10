from __future__ import absolute_import, division, print_function

from cryptoplay.bytes import to_byte_ints


class Bag(object):

    def __init__(self, **kw):
        for k in kw:
            setattr(self, k, kw[k])

    def __str__(self):
        return str(self.__dict__)

    def __repr__(self):
        return repr(self.__dict__)


class Bytes(object):

    def __init__(self, x=None):
        self.__bs = to_byte_ints(x) if x is not None else []

    @property
    def bs(self):
        return self.__bs

    def bin(self):
        return [bin(b)[2:].zfill(8) for b in self.bs]

    def hex(self):
        return [hex(b)[2:].zfill(2) for b in self.bs]

    def append(self, bs):
        self.bs.extend(to_byte_ints(bs))
        return self

    def __repr__(self):
        return repr(self.bs)

    def __str__(self):
        return str(self.bs)
