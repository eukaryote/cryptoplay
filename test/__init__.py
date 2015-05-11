from __future__ import absolute_import, division, print_function

from collections import namedtuple


cbcvectors = namedtuple('cbcvectors', ['key', 'vectors'])
cbcpoint = namedtuple('cbcpoint', ['iv', 'vector', 'ciphertext'])

ctrvectors = namedtuple('ctrvectors', ['key', 'nonce', 'vectors'])
ctrpoint = namedtuple('ctrpoint', ['vector', 'ciphertext'])
