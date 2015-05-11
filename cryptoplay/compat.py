from __future__ import absolute_import, division, print_function

try:
    range = xrange  # alias range as xrange under python2
except NameError:
    pass


try:
    integral_types = (int, long)
except NameError:
    integral_types = (int,)
