"""
aes_manual.py
Implementasi AES-128 MANUAL (tanpa library kripto apa pun).
 - Mode      : CBC + padding PKCS#7 (IV acak 16 byte di-prepend ke ciphertext)
 - Key       : string ASCII 16 karakter (otomatis dipad '0' / dipotong bila beda)
 - Plaintext : string ASCII
 - Ciphertext: string HEX
Satu-satunya modul bawaan yang dipakai: os (untuk os.urandom -> IV acak).
"""
import os

# GF(2^8)
def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r

# S-Box
def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def _build_sbox():
    """S-Box dihitung (invers multiplikatif GF(2^8) + transformasi affine)."""
    sbox = [0] * 256
    p = q = 1
    while True:
        # p *= 3
        p = (p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        # q /= 3
        q ^= (q << 1) & 0xFF
        q ^= (q << 2) & 0xFF
        q ^= (q << 4) & 0xFF
        if q & 0x80:
            q ^= 0x09
        x = q ^ _rotl8(q, 1) ^ _rotl8(q, 2) ^ _rotl8(q, 3) ^ _rotl8(q, 4)
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox

SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = []
_rc = 1
for _ in range(10):
    RCON.append(_rc)
    _rc = _xtime(_rc)

M2 = [_gmul(i, 2) for i in range(256)]
M3 = [_gmul(i, 3) for i in range(256)]
M9 = [_gmul(i, 9) for i in range(256)]
M11 = [_gmul(i, 11) for i in range(256)]
M13 = [_gmul(i, 13) for i in range(256)]
M14 = [_gmul(i, 14) for i in range(256)]

# Key schedule
def _expand_key(key16):
    w = [list(key16[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        t = w[i - 1][:]
        if i % 4 == 0:
            t = t[1:] + t[:1]                 # RotWord
            t = [SBOX[b] for b in t]          # SubWord
            t[0] ^= RCON[i // 4 - 1]          # Rcon
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk += w[4 * r + c]
        round_keys.append(rk)
    return round_keys

# Round functions
# state = list 16 byte, urutan kolom (state[r + 4*c])
def _add_round_key(s, rk):
    return [s[i] ^ rk[i] for i in range(16)]

def _sub_bytes(s):
    return [SBOX[b] for b in s]

def _inv_sub_bytes(s):
    return [INV_SBOX[b] for b in s]

def _shift_rows(s):
    n = [0] * 16
    for r in range(4):
        for c in range(4):
            n[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return n

def _inv_shift_rows(s):
    n = [0] * 16
    for r in range(4):
        for c in range(4):
            n[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    return n

def _mix_columns(s):
    n = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        n[4 * c + 0] = M2[a0] ^ M3[a1] ^ a2 ^ a3
        n[4 * c + 1] = a0 ^ M2[a1] ^ M3[a2] ^ a3
        n[4 * c + 2] = a0 ^ a1 ^ M2[a2] ^ M3[a3]
        n[4 * c + 3] = M3[a0] ^ a1 ^ a2 ^ M2[a3]
    return n

def _inv_mix_columns(s):
    n = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c:4 * c + 4]
        n[4 * c + 0] = M14[a0] ^ M11[a1] ^ M13[a2] ^ M9[a3]
        n[4 * c + 1] = M9[a0] ^ M14[a1] ^ M11[a2] ^ M13[a3]
        n[4 * c + 2] = M13[a0] ^ M9[a1] ^ M14[a2] ^ M11[a3]
        n[4 * c + 3] = M11[a0] ^ M13[a1] ^ M9[a2] ^ M14[a3]
    return n

# Blok tunggal
def encrypt_block(block16, round_keys):
    s = _add_round_key(list(block16), round_keys[0])
    for r in range(1, 10):
        s = _sub_bytes(s)
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = _add_round_key(s, round_keys[r])
    s = _sub_bytes(s)
    s = _shift_rows(s)
    s = _add_round_key(s, round_keys[10])
    return bytes(s)

def decrypt_block(block16, round_keys):
    s = _add_round_key(list(block16), round_keys[10])
    for r in range(9, 0, -1):
        s = _inv_shift_rows(s)
        s = _inv_sub_bytes(s)
        s = _add_round_key(s, round_keys[r])
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = _inv_sub_bytes(s)
    s = _add_round_key(s, round_keys[0])
    return bytes(s)

# Padding & CBC
def _pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n

def _unpad(data):
    if not data or len(data) % 16 != 0:
        raise ValueError("panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("padding tidak valid (key salah / data rusak)")
    return data[:-n]

def fit_key(key_ascii):
    """Key ASCII -> tepat 16 byte (pad '0' atau dipotong)."""
    kb = key_ascii.encode("ascii")
    return (kb + b"0" * 16)[:16]

def encrypt_bytes(key_ascii, data):
    rk = _expand_key(fit_key(key_ascii))
    iv = os.urandom(16)
    prev = iv
    out = bytearray(iv)
    data = _pad(data)
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = encrypt_block(blk, rk)
        out += prev
    return bytes(out)

def decrypt_bytes(key_ascii, data):
    if len(data) < 32 or len(data) % 16 != 0:
        raise ValueError("ciphertext tidak valid")
    rk = _expand_key(fit_key(key_ascii))
    prev = data[:16]
    out = bytearray()
    for i in range(16, len(data), 16):
        c = data[i:i + 16]
        d = decrypt_block(c, rk)
        out += bytes(a ^ b for a, b in zip(d, prev))
        prev = c
    return _unpad(bytes(out))

# API teks <-> hex
def encrypt_text(key_ascii, plaintext_ascii):
    """plaintext ASCII -> ciphertext HEX (IV + ciphertext)."""
    return encrypt_bytes(key_ascii, plaintext_ascii.encode("ascii")).hex()

def decrypt_text(key_ascii, cipher_hex):
    """ciphertext HEX -> plaintext ASCII."""
    return decrypt_bytes(key_ascii, bytes.fromhex(cipher_hex)).decode("ascii")


# Self test
if __name__ == "__main__":
    # Test vector FIPS-197 Appendix C.1
    key = bytes(range(16))
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    expect = "69c4e0d86a7b0430d8cdb78070b4c55a"
    rk = _expand_key(key)
    ct = encrypt_block(pt, rk)
    print("Encrypt block :", ct.hex(), "OK" if ct.hex() == expect else "GAGAL")
    print("Decrypt block :", decrypt_block(ct, rk).hex(),
          "OK" if decrypt_block(ct, rk) == pt else "GAGAL")
    c = encrypt_text("kunciRahasia1234", "Halo ini tes CBC AES manual!")
    print("CBC hex       :", c)
    print("CBC dekripsi  :", decrypt_text("kunciRahasia1234", c))