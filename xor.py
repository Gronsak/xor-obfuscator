def xor_obfuscate(data:bytes, key:bytes):
    out = []
    key_len = len(key)

    for i, byte in enumerate(data):
        out.append(byte ^ key[i % key_len])
    return bytes(out)