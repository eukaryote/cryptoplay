from __future__ import absolute_import, division, print_function

from base64 import b16decode

from Crypto import Random
from Crypto.Cipher import AES

from cryptoplay.compat import integral_types
from cryptoplay.util import split_at
from cryptoplay.pad import pad_pkcs5
from cryptoplay.bytes import xor_, bytes_to_int, int_to_byte_ints

BLOCKSIZE = AES.block_size
KEYSIZES = AES.key_size


def gen_iv(blocksize=BLOCKSIZE):
    return Random.new().read(blocksize)


def split_block(elems):
    return split_at(elems, BLOCKSIZE)


def key2bytes(key):
    keybytes = b16decode(key, True)
    if len(keybytes) not in KEYSIZES:
        raise ValueError('Invalid key length: %s' % len(keybytes))
    return keybytes


def iv2bytes(iv):
    if iv is not None:
        iv = b16decode(iv, True)
    else:
        iv = gen_iv(BLOCKSIZE)
    if len(iv) != BLOCKSIZE:
        raise ValueError('Invalid iv of length %s' % len(iv))
    elif not isinstance(iv, str):
        raise ValueError('Invalid iv: %s' % (iv,))
    return iv


def aes_pad(plaintext_bytes):
    num_bytes = len(plaintext_bytes)
    plaintext_bytes = pad_pkcs5(plaintext_bytes, blocksize=BLOCKSIZE)
    assert len(plaintext_bytes) > num_bytes
    return plaintext_bytes


def aes_cbc_encrypt(key, plaintext, iv=None, pad=True):
    """

    Encrypt the `plaintext` using the given `key` and `iv` (if given, or using
    a random initialization vector if not) using AES in CBC mode, optionally
    padding using pkcs5 if `pad` is True (plaintext must be exact multiple of
    `blocksize` if `pad` is False).

    """
    keybytes = key2bytes(key)
    ivbytes = iv2bytes(iv)
    ptbytes = b16decode(plaintext, True)

    if pad:
        ptbytes = aes_pad(ptbytes)

    if len(ptbytes) % BLOCKSIZE != 0:
        raise ValueError("Invalid plaintext not a multiple of 16: %s" %
                         ptbytes)

    ciphertext_blocks = [ivbytes]
    while True:
        ptblock, ptbytes = split_block(ptbytes)
        block_input = ''.join(xor_(list(ciphertext_blocks[-1]),
                                   list(ptblock)))
        block_enc_output = AES.new(keybytes).encrypt(block_input)
        ciphertext_blocks.append(block_enc_output)
        if not ptbytes:
            break
    return ''.join(ciphertext_blocks)


def aes_cbc_decrypt(key, ciphertext, raw=False):
    """
    Decrypt the AES-CBC-encrypted `ciphertext` using the given `key`,
    stripping off the IV and the pkcs5 padding bytes if `raw` is false.
    """
    keybytes = key2bytes(key)
    ctbytes = b16decode(ciphertext, True)

    if len(ctbytes) % BLOCKSIZE != 0:
        raise ValueError('Invalid ciphertext length: %s' % (ciphertext,))

    iv, ctbytes = split_block(ctbytes)
    plaintext_blocks = [iv]
    prev_ciphertext = iv
    while True:
        ctblock, ctbytes = split_block(ctbytes)
        block_bytes = AES.new(keybytes).decrypt(ctblock)
        block_bytes = ''.join(xor_(list(prev_ciphertext),
                                   list(block_bytes)))
        plaintext_blocks.append(block_bytes)
        prev_ciphertext = ctblock
        if not ctbytes:
            break

    if not raw:
        plaintext_blocks = plaintext_blocks[1:]  # strip off IV
        last_block = plaintext_blocks[-1]
        last_byte = ord(last_block[-1])
        if last_byte == 0 or last_byte > BLOCKSIZE:
            raise ValueError("Invalid last byte: %s" % last_byte)
        last_block_bytes, last_block_padding = (last_block[:-last_byte],
                                                last_block[-last_byte:])
        padding_bytes = set(list(last_block_padding))
        if len(padding_bytes) != 1:
            raise ValueError("Invalid padding: %s" % last_block_padding)
        if last_block_bytes:
            plaintext_blocks[-1] = last_block_bytes
        else:
            plaintext_blocks.pop()

    return ''.join(plaintext_blocks)


def aes_ctr_incr(ctrbytes):
    if not isinstance(ctrbytes, str):
        raise ValueError("invalid ctr: %s" % ctrbytes)
    size = len(ctrbytes)
    assert size == BLOCKSIZE // 2
    n = bytes_to_int(ctrbytes)
    assert isinstance(n, integral_types)
    n = (n + 1) % (2 ** (size * 8))
    res = int_to_byte_ints(n)
    if len(res) < BLOCKSIZE // 2:
        res = ([0] * (BLOCKSIZE // 2 - len(res))) + res
    return ''.join(map(chr, res))


def aes_ctr_encrypt(key, plaintext, nonce_ctr):
    keybytes = key2bytes(key)
    if not nonce_ctr:
        raise ValueError()
    nonce_ctr_bytes = iv2bytes(nonce_ctr)
    nonce, ctr = split_at(nonce_ctr_bytes)
    ptbytes = b16decode(plaintext, True)

    ciphertext_blocks = []
    ptblock, ptbytes = split_block(ptbytes)
    while ptblock:
        cbytes = AES.new(keybytes).encrypt(nonce + ctr)
        ctext_bytes = ''.join(xor_(list(ptblock),
                                   list(cbytes),
                                   truncate=True))
        ciphertext_blocks.append(ctext_bytes)
        if not ptbytes:
            break
        ctr = aes_ctr_incr(ctr)
        ptblock, ptbytes = split_block(ptbytes)
    return ''.join(ciphertext_blocks)


aes_ctr_decrypt = aes_ctr_encrypt
