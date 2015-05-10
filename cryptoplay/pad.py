DEFAULT_BLOCKSIZE = 16


def pad_pkcs5(block, blocksize=DEFAULT_BLOCKSIZE):
    aslist = False
    if isinstance(block, list):
        aslist = True
        block = block[:]
    else:
        block = list(block)
    if block and not isinstance(block[0], str):
        raise ValueError("block contains non-string type: %s" % type(block[0]))
    num_missing_bytes = len(block) % blocksize
    if num_missing_bytes == 0:
        block.extend([chr(blocksize)] * blocksize)
    else:
        block.extend([chr(blocksize - num_missing_bytes)] *
                     (blocksize - num_missing_bytes))
    return block if aslist else ''.join(block)
