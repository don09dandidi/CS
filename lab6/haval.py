#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAVAL — pure Python implementation (Y. Zheng, J. Pieprzyk, J. Seberry, AUSCRYPT'92).

Supports HAVAL-224 and HAVAL-256 with 3, 4 or 5 passes. The lab uses
HAVAL-224,4 (224-bit digest, 4 passes), i = (22 mod 24) + 1 = 23.

The 8-word initial value and the 4 x 32 round constants are the first
32-bit words of the fractional part of pi; instead of hard-coding them they are
computed below with Machin's formula, pi = 16 arctan(1/5) - 4 arctan(1/239).

Verified against PHP's hash('haval224,4', ...) and hash('haval256,N', ...) on many inputs.

Author: Strunga Daniel-Ioan, FAF-242
"""

MASK = 0xFFFFFFFF


def _pi_words(count: int):
    """First `count` 32-bit words of the fractional part of pi."""
    bits = 32 * count + 64

    def arctan_inv(x: int, one: int) -> int:
        s = t = one // x
        x2, n, sign = x * x, 1, -1
        while t:
            t //= x2
            n += 2
            s += sign * (t // n)
            sign = -sign
        return s

    one = 1 << bits
    pi = 4 * (4 * arctan_inv(5, one) - arctan_inv(239, one))
    frac = pi - (3 << bits)
    return [(frac >> (bits - 32 * (i + 1))) & MASK for i in range(count)]


_PI = _pi_words(8 + 4 * 32)
IV = _PI[:8]                                               # 243F6A88 85A308D3 ...
CONST = [None] + [_PI[8 + 32 * k: 8 + 32 * (k + 1)] for k in range(4)]   # passes 2..5

# Message word order for passes 2..5 (pass 1 uses 0..31)
ORDER = [
    list(range(32)),
    [5, 14, 26, 18, 11, 28, 7, 16, 0, 23, 20, 22, 1, 10, 4, 8,
     30, 3, 21, 9, 17, 24, 29, 6, 19, 12, 15, 13, 2, 25, 31, 27],
    [19, 9, 4, 20, 28, 17, 8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
     31, 15, 7, 3, 1, 0, 18, 27, 13, 6, 21, 10, 23, 11, 5, 2],
    [24, 4, 0, 14, 2, 7, 28, 23, 26, 6, 30, 20, 18, 25, 19, 3,
     22, 11, 31, 21, 8, 27, 12, 9, 1, 29, 5, 15, 17, 10, 16, 13],
    [27, 3, 21, 26, 17, 11, 20, 29, 19, 0, 12, 7, 13, 8, 31, 10,
     5, 9, 14, 30, 18, 6, 28, 24, 2, 23, 16, 22, 4, 1, 25, 15],
]


# Boolean functions F1..F5, arguments in the order (x6, x5, x4, x3, x2, x1, x0)
def _f1(x6, x5, x4, x3, x2, x1, x0):
    return (x1 & (x0 ^ x4)) ^ (x2 & x5) ^ (x3 & x6) ^ x0


def _f2(x6, x5, x4, x3, x2, x1, x0):
    return (x2 & ((x1 & ~x3) ^ (x4 & x5) ^ x6 ^ x0)) ^ (x4 & (x1 ^ x5)) ^ (x3 & x5) ^ x0


def _f3(x6, x5, x4, x3, x2, x1, x0):
    return (x3 & ((x1 & x2) ^ x6 ^ x0)) ^ (x1 & x4) ^ (x2 & x5) ^ x0


def _f4(x6, x5, x4, x3, x2, x1, x0):
    return ((x4 & ((x5 & ~x2) ^ (x3 & ~x6) ^ x1 ^ x6 ^ x0))
            ^ (x3 & ((x1 & x2) ^ x5 ^ x6)) ^ (x2 & x6) ^ x0)


def _f5(x6, x5, x4, x3, x2, x1, x0):
    return (x0 & ((x1 & x2 & x3) ^ ~x5)) ^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6)


_F = [_f1, _f2, _f3, _f4, _f5]

# Permutations phi_{passes, pass}: positions (in x6..x0 order) passed to F.
# Each tuple lists which x_j goes to the arguments (x6, x5, x4, x3, x2, x1, x0) of F.
_PHI = {
    3: [(1, 0, 3, 5, 6, 2, 4), (4, 2, 1, 0, 5, 3, 6), (6, 1, 2, 3, 4, 5, 0)],
    4: [(2, 6, 1, 4, 5, 3, 0), (3, 5, 2, 0, 1, 6, 4), (1, 4, 3, 6, 0, 2, 5),
        (6, 4, 0, 5, 2, 1, 3)],
    5: [(3, 4, 1, 0, 5, 2, 6), (6, 2, 1, 0, 3, 4, 5), (2, 6, 0, 4, 3, 1, 5),
        (1, 5, 3, 2, 0, 4, 6), (2, 5, 0, 6, 4, 3, 1)],
}


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK


def _compress(state, block: bytes, passes: int):
    w = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(32)]
    t = list(state)                         # t[0..7]
    for p in range(passes):
        f, phi = _F[p], _PHI[passes][p]
        for s in range(32):
            # registers seen as x7..x0 rotate by one position at every step
            x = [t[(j - s) % 8] for j in range(8)]          # x[j] = x_j
            args = [x[j] for j in phi]
            temp = f(*args) & MASK
            new = (_rotr(temp, 7) + _rotr(x[7], 11) + w[ORDER[p][s]]) & MASK
            if p > 0:
                new = (new + CONST[p][s]) & MASK
            t[(7 - s) % 8] = new
    return [(a + b) & MASK for a, b in zip(state, t)]


def _tailor(s, bits: int):
    """Folds the 256-bit chaining value to the requested output length.
    Only the 256- and 224-bit variants are needed for this laboratory."""
    if bits == 256:
        return s
    if bits == 224:
        t = s[7]
        return [(s[0] + ((t >> 27) & 0x1F)) & MASK, (s[1] + ((t >> 22) & 0x1F)) & MASK,
                (s[2] + ((t >> 18) & 0x0F)) & MASK, (s[3] + ((t >> 13) & 0x1F)) & MASK,
                (s[4] + ((t >> 9) & 0x0F)) & MASK, (s[5] + ((t >> 4) & 0x1F)) & MASK,
                (s[6] + (t & 0x0F)) & MASK]
    raise ValueError("only HAVAL-224 and HAVAL-256 are implemented")


def haval(data: bytes, bits: int = 224, passes: int = 4) -> bytes:
    if passes not in (3, 4, 5):
        raise ValueError("passes must be 3, 4 or 5")
    version = 1
    n = len(data)
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % 128 != 118:
        msg.append(0)
    msg.append(((bits & 0x3) << 6) | (passes << 3) | version)
    msg.append((bits >> 2) & 0xFF)
    msg += (8 * n).to_bytes(8, "little")
    state = list(IV)
    for off in range(0, len(msg), 128):
        state = _compress(state, bytes(msg[off:off + 128]), passes)
    return b"".join(w.to_bytes(4, "little") for w in _tailor(state, bits))


def haval224_4(data: bytes) -> str:
    """HAVAL-224, 4 passes — hex digest (same notation as PHP 'haval224,4')."""
    return haval(data, 224, 4).hex()


if __name__ == "__main__":
    import sys
    data = sys.stdin.buffer.read() if len(sys.argv) < 2 else sys.argv[1].encode()
    print(haval224_4(data))
