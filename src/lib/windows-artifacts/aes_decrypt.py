"""
Minimal pure-Python AES (128/192/256) CBC decryption — FIPS-197, decrypt
direction only. Used to de-obfuscate OneDrive ODL log strings with the
per-folder general.keystore key (see app-artifact-parse.py). Kept
dependency-free on purpose: the Windows Artifacts venv has no crypto
library, and the volume here (short log tokens) is tiny, so speed is not a
concern.
"""

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
_INV_SBOX = bytes(_SBOX.index(i) for i in range(256))
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


_M9, _M11, _M13, _M14 = ([_mul(i, k) for i in range(256)] for k in (9, 11, 13, 14))


def _expand_key(key):
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    rounds = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        t = list(w[i - 1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        w.append([a ^ b for a, b in zip(w[i - nk], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(rounds + 1)], rounds


def _decrypt_block(block, round_keys, rounds):
    s = [b ^ k for b, k in zip(block, round_keys[rounds])]
    for r in range(rounds - 1, -1, -1):
        # InvShiftRows (state is column-major: s[row + 4*col])
        s = [s[(i - 4 * (i % 4)) % 16] for i in range(16)]
        s = [_INV_SBOX[b] for b in s]
        s = [b ^ k for b, k in zip(s, round_keys[r])]
        if r:
            out = []
            for c in range(4):
                a0, a1, a2, a3 = s[4 * c:4 * c + 4]
                out += [
                    _M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3],
                    _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3],
                    _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3],
                    _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3],
                ]
            s = out
    return bytes(s)


class AesCbcDecryptor:
    def __init__(self, key):
        self._round_keys, self._rounds = _expand_key(bytes(key))

    def decrypt(self, data, iv=b"\0" * 16):
        """CBC-decrypts `data` (multiple of 16 bytes); returns the raw
        plaintext including padding, or None on bad length."""
        if not data or len(data) % 16:
            return None
        out, prev = bytearray(), iv
        for i in range(0, len(data), 16):
            block = data[i:i + 16]
            out += bytes(a ^ b for a, b in zip(_decrypt_block(block, self._round_keys, self._rounds), prev))
            prev = block
        return bytes(out)


def unpad_pkcs7(data):
    if not data:
        return None
    n = data[-1]
    if not 1 <= n <= 16 or data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]
