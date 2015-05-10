from __future__ import absolute_import, division, print_function

from base64 import b16decode

from Crypto import Random
from Crypto.Cipher import AES

from cryptoplay.pad import pad_pkcs5
from cryptoplay.bytes import xor_

BLOCKSIZE = AES.block_size
KEYSIZES = AES.key_size


def gen_iv(blocksize=BLOCKSIZE):
    return Random.new().read(blocksize)


def aes_cbc_encrypt(key, plaintext, iv=None, pad=True):
    """

    Encrypt the `plaintext` using the given `key` and `iv` (if given, or using
    a random initialization vector if not) using AES in CBC mode, optionally
    padding using pkcs5 if `pad` is True (plaintext must be exact multiple of
    `blocksize` if `pad` is False).

    """
    keybytes = b16decode(key, True)
    if len(keybytes) not in KEYSIZES:
        raise ValueError('Invalid key length: %s' % len(keybytes))

    if iv is not None:
        iv = b16decode(iv, True)
    else:
        iv = gen_iv(BLOCKSIZE)
    assert len(iv) == BLOCKSIZE
    assert isinstance(iv, str)

    ptbytes = b16decode(plaintext, True)

    if pad:
        num_ptbytes = len(ptbytes)
        ptbytes = pad_pkcs5(ptbytes, blocksize=BLOCKSIZE)
        assert len(ptbytes) > num_ptbytes

    assert len(ptbytes) % BLOCKSIZE == 0

    ciphertext_blocks = [iv]
    while True:
        ptblock, ptbytes = ptbytes[:BLOCKSIZE], ptbytes[BLOCKSIZE:]
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
    keybytes = b16decode(key, True)
    if len(keybytes) not in KEYSIZES:
        raise ValueError('Invalid key length: %s' % len(keybytes))

    ctbytes = b16decode(ciphertext, True)

    if len(ctbytes) % BLOCKSIZE != 0:
        raise ValueError('Invalid ciphertext length: %s' % (ciphertext,))

    iv, ctbytes = ctbytes[:BLOCKSIZE], ctbytes[BLOCKSIZE:]
    plaintext_blocks = [iv]
    prev_ciphertext = iv
    while True:
        ctblock, ctbytes = ctbytes[:BLOCKSIZE], ctbytes[BLOCKSIZE:]
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
