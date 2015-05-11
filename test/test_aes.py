from __future__ import absolute_import, division, print_function

from base64 import b16encode, b16decode

from Crypto.Cipher import AES

import cryptoplay.aes as A
import cryptoplay.bytes as B
from cryptoplay.util import split_at

from test import cbcvectors, cbcpoint, ctrvectors, ctrpoint


AES_CBC_128_NIST_VECTORS = cbcvectors(
    key='2b7e151628aed2a6abf7158809cf4f3c',
    vectors=(
        cbcpoint(
            iv='000102030405060708090A0B0C0D0E0F'.upper(),
            vector='6bc1bee22e409f96e93d7e117393172a'.upper(),
            ciphertext='7649abac8119b246cee98e9b12e9197d'.upper()),
        cbcpoint(
            iv='7649ABAC8119B246CEE98E9B12E9197D'.upper(),
            vector='ae2d8a571e03ac9c9eb76fac45af8e51'.upper(),
            ciphertext='5086cb9b507219ee95db113a917678b2'.upper()),
        cbcpoint(
            iv='5086CB9B507219EE95DB113A917678B2'.upper(),
            vector='30c81c46a35ce411e5fbc1191a0a52ef'.upper(),
            ciphertext='73bed6b8e3c1743b7116e69e22229516'.upper()),
        cbcpoint(
            iv='73BED6B8E3C1743B7116E69E22229516'.upper(),
            vector='f69f2445df4f9b17ad2b417be66c3710'.upper(),
            ciphertext='3ff1caa1681fac09120eca307586e1a7'.upper())
    )
)

AES_CBC_192_NIST_VECTORS = cbcvectors(
    key='8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
    vectors=(
        cbcpoint(
            iv='000102030405060708090A0B0C0D0E0F'.upper(),
            vector='6bc1bee22e409f96e93d7e117393172a'.upper(),
            ciphertext='4f021db243bc633d7178183a9fa071e8'.upper()),
        cbcpoint(
            iv='4F021DB243BC633D7178183A9FA071E8'.upper(),
            vector='ae2d8a571e03ac9c9eb76fac45af8e51'.upper(),
            ciphertext='b4d9ada9ad7dedf4e5e738763f69145a'.upper()),
        cbcpoint(
            iv='B4D9ADA9AD7DEDF4E5E738763F69145A'.upper(),
            vector='30c81c46a35ce411e5fbc1191a0a52ef'.upper(),
            ciphertext='571b242012fb7ae07fa9baac3df102e0'.upper()),
        cbcpoint(
            iv='571B242012FB7AE07FA9BAAC3DF102E0'.upper(),
            vector='f69f2445df4f9b17ad2b417be66c3710'.upper(),
            ciphertext='08b0e27988598881d920a9e64f5615cd'.upper())
    )
)

AES_CBC_256_NIST_VECTORS = cbcvectors(
    key='603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    vectors=(
        cbcpoint(
            iv='000102030405060708090A0B0C0D0E0F'.upper(),
            vector='6bc1bee22e409f96e93d7e117393172a'.upper(),
            ciphertext='f58c4c04d6e5f1ba779eabfb5f7bfbd6'.upper()),
        cbcpoint(
            iv='F58C4C04D6E5F1BA779EABFB5F7BFBD6'.upper(),
            vector='ae2d8a571e03ac9c9eb76fac45af8e51'.upper(),
            ciphertext='9cfc4e967edb808d679f777bc6702c7d'.upper()),
        cbcpoint(
            iv='9CFC4E967EDB808D679F777BC6702C7D'.upper(),
            vector='30c81c46a35ce411e5fbc1191a0a52ef'.upper(),
            ciphertext='39f23369a9d9bacfa530e26304231461'.upper()),
        cbcpoint(
            iv='39F23369A9D9BACFA530E26304231461'.upper(),
            vector='f69f2445df4f9b17ad2b417be66c3710'.upper(),
            ciphertext='b2eb05e2c39be9fcda6c19078c6a9d1b'.upper())
    )
)

AES_CTR_128_NIST_VECTORS = ctrvectors(
    key='2b7e151628aed2a6abf7158809cf4f3c',
    nonce='f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    vectors=(
        ctrpoint(
            vector='6bc1bee22e409f96e93d7e117393172a',
            ciphertext='874d6191b620e3261bef6864990db6ce'),
        ctrpoint(
            vector='ae2d8a571e03ac9c9eb76fac45af8e51',
            ciphertext='9806f66b7970fdff8617187bb9fffdff'),
        ctrpoint(
            vector='30c81c46a35ce411e5fbc1191a0a52ef',
            ciphertext='5ae4df3edbd5d35e5b4f09020db03eab'),
        ctrpoint(
            vector='f69f2445df4f9b17ad2b417be66c3710',
            ciphertext='1e031dda2fbe03d1792170a0f3009cee')
    )
)

AES_CTR_192_NIST_VECTORS = ctrvectors(
    key='8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b',
    nonce='f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    vectors=(
        ctrpoint(
            vector='6bc1bee22e409f96e93d7e117393172a'.upper(),
            ciphertext='1abc932417521ca24f2b0459fe7e6e0b'.upper()),
        ctrpoint(
            vector='ae2d8a571e03ac9c9eb76fac45af8e51'.upper(),
            ciphertext='090339ec0aa6faefd5ccc2c6f4ce8e94'.upper()),
        ctrpoint(
            vector='30c81c46a35ce411e5fbc1191a0a52ef'.upper(),
            ciphertext='1e36b26bd1ebc670d1bd1d665620abf7'.upper()),
        ctrpoint(
            vector='f69f2445df4f9b17ad2b417be66c3710'.upper(),
            ciphertext='4f78a7f6d29809585a97daec58c6b050'.upper())
    )
)

AES_CTR_256_NIST_VECTORS = ctrvectors(
    key='603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    nonce='f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    vectors=(
        ctrpoint(
            vector='6bc1bee22e409f96e93d7e117393172a'.upper(),
            ciphertext='601ec313775789a5b7a7f504bbf3d228'.upper()),
        ctrpoint(
            vector='ae2d8a571e03ac9c9eb76fac45af8e51'.upper(),
            ciphertext='f443e3ca4d62b59aca84e990cacaf5c5'.upper()),
        ctrpoint(
            vector='30c81c46a35ce411e5fbc1191a0a52ef'.upper(),
            ciphertext='2b0930daa23de94ce87017ba2d84988d'.upper()),
        ctrpoint(
            vector='f69f2445df4f9b17ad2b417be66c3710'.upper(),
            ciphertext='dfc9c58db67aada613c2dd08457941a6'.upper())
    )
)


def enc_aes_cbc_padding_block(key, last_block):
    """
    For the given key and last block of AES ciphertext in CBC mode, generate
    the ciphertext block for a full last-block of padding.
    """
    keybytes = b16decode(key, True)
    blocksize = A.BLOCKSIZE
    bs = b16decode(last_block, True)
    assert len(bs) == A.BLOCKSIZE
    xbytes = ''.join(chr(b) for b in B.xor_(map(ord, bs),
                                            [blocksize] * blocksize))
    return AES.new(keybytes).encrypt(xbytes)


def test_gen_iv_default_blocksize():
    iv = A.gen_iv()
    assert len(iv) == A.BLOCKSIZE
    assert isinstance(iv, str)


def test_aes_ctr_incr():
    bs = map(chr, [1, 1, 1, 1, 1, 1, 1, 1])
    n = 1
    for i in range(len(bs) - 1):
        n = 256 * n + 1
    assert n == B.bytes_to_int(bs)
    ctr = ''.join(bs)
    ctr2 = A.aes_ctr_incr(ctr)
    assert B.bytes_to_int(ctr2) == n + 1


def test_aes_ctr_incr0():
    bs = map(chr, [0, 0, 0, 0, 0, 0, 0, 1])
    n = 1
    assert n == B.bytes_to_int(bs)
    ctr = ''.join(bs)
    assert b16encode(ctr) == '0000000000000001'
    ctr2 = A.aes_ctr_incr(ctr)
    assert b16encode(ctr2) == '0000000000000002'
    assert B.bytes_to_int(ctr2) == n + 1


def test_aes_ctr_incr_wraparound():
    n = (2 ** 64) - 2
    print('n=%s' % n)
    bs = B.int_to_byte_ints(n)
    print('bs=%s' % bs)
    ctr = ''.join(map(chr, bs))
    assert B.bytes_to_int(bs) == n
    assert len(bs) == A.BLOCKSIZE // 2
    ctr2 = A.aes_ctr_incr(ctr)
    assert isinstance(ctr2, str)
    assert n + 1 == B.bytes_to_int(ctr2)
    ctr3 = A.aes_ctr_incr(ctr2)
    assert isinstance(ctr3, str)
    assert 0 == B.bytes_to_int(ctr3)


def test_aes_ctr_incr_nist():
    nist_iv = 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff'
    nonce, ctr = [b16decode(s, True) for s in split_at(nist_iv,
                                                       len(nist_iv) // 2)]
    ctr2 = A.aes_ctr_incr(ctr)
    assert B.bytes_to_int(ctr) + 1 == B.bytes_to_int(ctr2)
    ctr3 = A.aes_ctr_incr(ctr2)
    assert B.bytes_to_int(ctr2) + 1 == B.bytes_to_int(ctr3)


def run_aes_cbc_encrypt_nopad_nist_test(testvectors, test_num):
    key = testvectors.key
    blocksize = A.BLOCKSIZE
    iv, vector, ciphertext = testvectors.vectors[test_num]
    result = A.aes_cbc_encrypt(key, vector, iv=iv, pad=False)
    result_iv, result_ciphertext = result[:blocksize], result[blocksize:]
    assert b16encode(result_iv) == iv
    assert b16encode(result_ciphertext) == ciphertext


def run_aes_cbc_encrypt_pad_nist_test(testvectors, n):
    key = testvectors.key
    blocksize = A.BLOCKSIZE
    iv, vector, ciphertext = testvectors.vectors[n]
    result = A.aes_cbc_encrypt(key, vector, iv=iv, pad=True)
    result_iv = result[:blocksize]
    result_ciphertext = result[blocksize:blocksize * 2]
    result_padding = result[blocksize * 2:]
    assert b16encode(result_iv) == iv
    assert b16encode(result_ciphertext) == ciphertext
    last_block = b16encode(result_ciphertext)
    print('key=%s, last_block=%s' % (len(key), len(last_block)))
    expected_padding_bytes = enc_aes_cbc_padding_block(key, last_block)
    assert b16encode(result_padding) == b16encode(expected_padding_bytes)


def run_aes_cbc_decrypt_raw_nist_test(testvectors, n):
    key = testvectors.key
    blocksize = A.BLOCKSIZE
    iv, vector, ciphertext = testvectors.vectors[n]
    data = iv + ciphertext
    result = A.aes_cbc_decrypt(key, data, raw=True)
    assert len(result) == 2 * blocksize
    result_iv = result[:blocksize]
    result_plaintext = result[blocksize:]
    assert result_iv
    assert result_plaintext
    assert b16encode(result_iv) == iv
    assert result_plaintext == b16decode(vector, True)
    assert b16encode(result_plaintext) == vector


def run_aes_cbc_decrypt_noraw_nist_test(testvectors, n):
    key = testvectors.key
    blocksize = 16
    iv, vector, ciphertext = testvectors.vectors[n]
    padding = b16encode(enc_aes_cbc_padding_block(key, ciphertext))

    data = iv + ciphertext + padding
    result = A.aes_cbc_decrypt(key, data, raw=False)
    assert len(result) == blocksize
    assert result == b16decode(vector, True)
    assert b16encode(result) == vector


# TODO: change the way the tests are set up to avoid this hack
# of manipulating the nonce before each run to simulate one long
# run with nonce counter continually being updated rather than each
# run independent.
def incrhack(bytes, n):
    bytes = b16decode(bytes, True)
    head, tail = split_at(bytes)
    assert head + tail == bytes
    assert len(head) == A.BLOCKSIZE // 2
    assert len(tail) == A.BLOCKSIZE // 2
    for i in range(n):
        tail = A.aes_ctr_incr(tail)
    return b16encode(head + tail)


def run_aes_ctr_encrypt_nist_test(testvectors, test_num):
    key, nonce = testvectors.key, testvectors.nonce
    keybytes, noncebytes = b16decode(key, True), b16decode(nonce, True)
    assert len(keybytes) in A.KEYSIZES
    assert len(noncebytes) == A.BLOCKSIZE
    nonce = incrhack(nonce, test_num)
    vector, ciphertext = testvectors.vectors[test_num]
    result = A.aes_ctr_encrypt(key, vector, nonce_ctr=nonce)
    assert len(b16encode(result)) == len(vector)
    assert b16encode(result).lower() == ciphertext.lower()
    assert result == b16decode(ciphertext, True)


def test_aes_cbc_128_encrypt_nopad_nist0():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_128_NIST_VECTORS, 0)


def test_aes_cbc_128_encrypt_nopad_nist1():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_128_NIST_VECTORS, 1)


def test_aes_cbc_128_encrypt_nopad_nist2():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_128_NIST_VECTORS, 2)


def test_aes_cbc_128_encrypt_nopad_nist3():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_128_NIST_VECTORS, 3)


def test_aes_cbc_128_encrypt_pad_nist0():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_128_NIST_VECTORS, 0)


def test_aes_cbc_128_encrypt_pad_nist1():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_128_NIST_VECTORS, 1)


def test_aes_cbc_128_encrypt_pad_nist2():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_128_NIST_VECTORS, 2)


def test_aes_cbc_128_encrypt_pad_nist3():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_128_NIST_VECTORS, 3)


def test_aes_cbc_128decrypt_raw_nist0():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_128_NIST_VECTORS, 0)


def test_aes_cbc_128decrypt_raw_nist1():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_128_NIST_VECTORS, 1)


def test_aes_cbc_128decrypt_raw_nist2():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_128_NIST_VECTORS, 2)


def test_aes_cbc_128decrypt_raw_nist3():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_128_NIST_VECTORS, 3)


def test_aes_cbc_128decrypt_noraw_nist0():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_128_NIST_VECTORS, 0)


def test_aes_cbc_128decrypt_noraw_nist1():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_128_NIST_VECTORS, 1)


def test_aes_cbc_128decrypt_noraw_nist2():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_128_NIST_VECTORS, 2)


def test_aes_cbc_128decrypt_noraw_nist3():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_128_NIST_VECTORS, 3)


def test_aes_cbc_192_encrypt_nopad_nist0():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_192_NIST_VECTORS, 0)


def test_aes_cbc_192_encrypt_nopad_nist1():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_192_NIST_VECTORS, 1)


def test_aes_cbc_192_encrypt_nopad_nist2():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_192_NIST_VECTORS, 2)


def test_aes_cbc_192_encrypt_nopad_nist3():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_192_NIST_VECTORS, 3)


def test_aes_cbc_192_encrypt_pad_nist0():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_192_NIST_VECTORS, 0)


def test_aes_cbc_192_encrypt_pad_nist1():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_192_NIST_VECTORS, 1)


def test_aes_cbc_192_encrypt_pad_nist2():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_192_NIST_VECTORS, 2)


def test_aes_cbc_192_encrypt_pad_nist3():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_192_NIST_VECTORS, 3)


def test_aes_cbc_192decrypt_raw_nist0():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_192_NIST_VECTORS, 0)


def test_aes_cbc_192decrypt_raw_nist1():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_192_NIST_VECTORS, 1)


def test_aes_cbc_192decrypt_raw_nist2():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_192_NIST_VECTORS, 2)


def test_aes_cbc_192decrypt_raw_nist3():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_192_NIST_VECTORS, 3)


def test_aes_cbc_192decrypt_noraw_nist0():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_192_NIST_VECTORS, 0)


def test_aes_cbc_192decrypt_noraw_nist1():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_192_NIST_VECTORS, 1)


def test_aes_cbc_192decrypt_noraw_nist2():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_192_NIST_VECTORS, 2)


def test_aes_cbc_192decrypt_noraw_nist3():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_192_NIST_VECTORS, 3)


def test_aes_cbc_256_encrypt_nopad_nist0():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_256_NIST_VECTORS, 0)


def test_aes_cbc_256_encrypt_nopad_nist1():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_256_NIST_VECTORS, 1)


def test_aes_cbc_256_encrypt_nopad_nist2():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_256_NIST_VECTORS, 2)


def test_aes_cbc_256_encrypt_nopad_nist3():
    run_aes_cbc_encrypt_nopad_nist_test(AES_CBC_256_NIST_VECTORS, 3)


def test_aes_cbc_256_encrypt_pad_nist0():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_256_NIST_VECTORS, 0)


def test_aes_cbc_256_encrypt_pad_nist1():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_256_NIST_VECTORS, 1)


def test_aes_cbc_256_encrypt_pad_nist2():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_256_NIST_VECTORS, 2)


def test_aes_cbc_256_encrypt_pad_nist3():
    run_aes_cbc_encrypt_pad_nist_test(AES_CBC_256_NIST_VECTORS, 3)


def test_aes_cbc_256decrypt_raw_nist0():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_256_NIST_VECTORS, 0)


def test_aes_cbc_256decrypt_raw_nist1():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_256_NIST_VECTORS, 1)


def test_aes_cbc_256decrypt_raw_nist2():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_256_NIST_VECTORS, 2)


def test_aes_cbc_256decrypt_raw_nist3():
    run_aes_cbc_decrypt_raw_nist_test(AES_CBC_256_NIST_VECTORS, 3)


def test_aes_cbc_256decrypt_noraw_nist0():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_256_NIST_VECTORS, 0)


def test_aes_cbc_256decrypt_noraw_nist1():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_256_NIST_VECTORS, 1)


def test_aes_cbc_256decrypt_noraw_nist2():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_256_NIST_VECTORS, 2)


def test_aes_cbc_256decrypt_noraw_nist3():
    run_aes_cbc_decrypt_noraw_nist_test(AES_CBC_256_NIST_VECTORS, 3)


def test_aes_ctr_128_encrypt_nist0():
    run_aes_ctr_encrypt_nist_test(AES_CTR_128_NIST_VECTORS, 0)


def test_aes_ctr_128_encrypt_nist1():
    run_aes_ctr_encrypt_nist_test(AES_CTR_128_NIST_VECTORS, 1)


def test_aes_ctr_128_encrypt_nist2():
    run_aes_ctr_encrypt_nist_test(AES_CTR_128_NIST_VECTORS, 2)


def test_aes_ctr_128_encrypt_nist3():
    run_aes_ctr_encrypt_nist_test(AES_CTR_128_NIST_VECTORS, 3)


def test_aes_ctr_192_encrypt_nist0():
    run_aes_ctr_encrypt_nist_test(AES_CTR_192_NIST_VECTORS, 0)


def test_aes_ctr_192_encrypt_nist1():
    run_aes_ctr_encrypt_nist_test(AES_CTR_192_NIST_VECTORS, 1)


def test_aes_ctr_192_encrypt_nist2():
    run_aes_ctr_encrypt_nist_test(AES_CTR_192_NIST_VECTORS, 2)


def test_aes_ctr_192_encrypt_nist3():
    run_aes_ctr_encrypt_nist_test(AES_CTR_192_NIST_VECTORS, 3)


def test_aes_ctr_256_encrypt_nist0():
    run_aes_ctr_encrypt_nist_test(AES_CTR_256_NIST_VECTORS, 0)


def test_aes_ctr_256_encrypt_nist1():
    run_aes_ctr_encrypt_nist_test(AES_CTR_256_NIST_VECTORS, 1)


def test_aes_ctr_256_encrypt_nist2():
    run_aes_ctr_encrypt_nist_test(AES_CTR_256_NIST_VECTORS, 2)


def test_aes_ctr_256_encrypt_nist3():
    run_aes_ctr_encrypt_nist_test(AES_CTR_256_NIST_VECTORS, 3)
