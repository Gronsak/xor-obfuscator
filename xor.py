"""
Provides an xor_obfuscate function that obfuscates bytes with the key using xor.
"""
def xor_obfuscate(data:bytes, key:bytes) -> bytes:
    """Runs xor function on **data** using **key**s bytes.
    
    :param bytes data: bytes to xor.
    :param bytes key: bytes to be used as key in xor function.
    :return bytes: xor:ed bytes.
    """
    out = []
    key_len = len(key)

    for i, byte in enumerate(data):
        out.append(byte ^ key[i % key_len])
    return bytes(out)
