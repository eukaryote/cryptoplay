from __future__ import absolute_import, division, print_function

from collections import namedtuple


ciphervectors = namedtuple('ciphervectors', ['key', 'vectors'])
cipherpoint = namedtuple('cipherpoint', ['iv', 'vector', 'ciphertext'])
