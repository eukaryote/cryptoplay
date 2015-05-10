from __future__ import absolute_import, division, print_function

import cryptoplay.pad as P


def test_pad_pkcs5_non_blocksize_multiple():
    bs = [' ']
    num_bytes = len(bs)
    res = P.pad_pkcs5(bs, P.DEFAULT_BLOCKSIZE)
    delta = len(res) - num_bytes
    assert len(res) == P.DEFAULT_BLOCKSIZE
    assert delta + num_bytes == P.DEFAULT_BLOCKSIZE
    assert res[0] == ' '
    padding = res[num_bytes:]
    assert len(padding) == delta
    assert res[1:] == [chr(delta)] * delta


def test_pad_pkcs5_emptyblock():
    bs = []
    res = P.pad_pkcs5(bs, P.DEFAULT_BLOCKSIZE)
    assert res == [chr(P.DEFAULT_BLOCKSIZE)] * P.DEFAULT_BLOCKSIZE


def test_pad_pkcs5_fullblock():
    bs = [chr(0)] * P.DEFAULT_BLOCKSIZE
    res = P.pad_pkcs5(bs, P.DEFAULT_BLOCKSIZE)
    assert res == ([chr(0)] * P.DEFAULT_BLOCKSIZE +
                   [chr(P.DEFAULT_BLOCKSIZE)] * P.DEFAULT_BLOCKSIZE)


def test_pad_pkcs5_bytestring():
    bs = ''.join([chr(0)] * (P.DEFAULT_BLOCKSIZE // 2))
    res = P.pad_pkcs5(bs, P.DEFAULT_BLOCKSIZE)
    exp = ''.join([chr(0)] * (P.DEFAULT_BLOCKSIZE // 2) +
                  [chr(P.DEFAULT_BLOCKSIZE // 2)] * (P.DEFAULT_BLOCKSIZE // 2))
    assert res == exp
