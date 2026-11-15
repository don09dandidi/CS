#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lucrarea de laborator nr. 6: Funcții hash și semnături digitale

  k = 22 (numărul de ordine în lista grupei)
  Funcția hash: i = (k mod 24) + 1 = 23  ->  HAVAL-224,4 (în ambele liste)

  Sarcina 2  Semnătura RSA (n >= 3072 biți) a mesajului m din lab. 2
  Sarcina 3  Semnătura ElGamal (p de 2048 biți dat, g = 2) a aceluiași mesaj

Valoarea hash este folosită în reprezentarea zecimală. Calculele folosesc doar
aritmetica întregilor din Python; pașii echivalenți în Wolfram Language sunt în
wolfram/lab6.wl.

Autor: Strunga Daniel-Ioan, gr. FAF-242
Repository: https://github.com/don09dandidi/CS
"""

import json
import math
import secrets
import sys
from pathlib import Path

from haval import haval224_4

HERE = Path(__file__).resolve().parent
K_STUDENT = 22
HASH_INDEX = (K_STUDENT % 24) + 1          # 23 -> HAVAL-224,4

P = int(
    "3231700607131100730015351347782516336248805713348907517458843413926"
    "980683413621000279205636264016468545855635793533081692882902308057347"
    "262527355474246124574102620252791657297286270630032526342821314576693"
    "141422365422094111134862999165747826803423055308634905063555771221918"
    "789033272956969612974385624174123623722519734640269185579776797682301"
    "462539793305801522685873076119753243646747585546071504389684494036613"
    "049769781285429595865959756705128385213278446852292550456827287911372"
    "009893187395914337417583782600027803497319855206060753323412260325468"
    "4088120031105907484281003994966956119696956248629032338072839127039"
)
G = 2
assert P.bit_length() == 2048


# ---------------------------------------------------------------------------
def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % q == 0:
            return n == q
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def random_prime(bits: int) -> int:
    while True:
        cand = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if is_probable_prime(cand):
            return cand


def random_in(lo: int, hi: int) -> int:
    return lo + secrets.randbelow(hi - lo + 1)


def hash_message(data: bytes):
    hx = haval224_4(data)
    return hx.upper(), int(hx, 16)


# ---------------------------------------------------------------------------
# Sarcina 2 — semnătura RSA
# ---------------------------------------------------------------------------
def rsa_signature(h: int, h_fake: int) -> dict:
    p = random_prime(1536)
    q = random_prime(1536)
    while q == p:
        q = random_prime(1536)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    assert math.gcd(e, phi) == 1
    d = pow(e, -1, phi)
    assert h < n
    s = pow(h, d, n)                     # semnătura  s = h^d mod n
    h_check = pow(s, e, n)               # verificare h' = s^e mod n
    return dict(p=p, q=q, n=n, n_bits=n.bit_length(), phi=phi, e=e, d=d, s=s,
                h_check=h_check, valid=(h_check == h), valid_fake=(h_check == h_fake))


# ---------------------------------------------------------------------------
# Sarcina 3 — semnătura ElGamal
# ---------------------------------------------------------------------------
def elgamal_signature(h: int, h_fake: int) -> dict:
    x = random_in(2, P - 2)              # cheia privată
    y = pow(G, x, P)                     # cheia publică y = g^x mod p
    while True:                          # k aleator cu gcd(k, p-1) = 1
        k = random_in(2, P - 2)
        if math.gcd(k, P - 1) == 1:
            break
    k_inv = pow(k, -1, P - 1)
    r = pow(G, k, P)                     # r = g^k mod p
    s = ((h - x * r) * k_inv) % (P - 1)  # s = (h - x*r) * k^-1 mod (p-1)
    assert 0 < r < P and s != 0
    left = pow(G, h, P)                  # g^h mod p
    right = (pow(y, r, P) * pow(r, s, P)) % P   # y^r * r^s mod p
    left_fake = pow(G, h_fake, P)
    return dict(p=P, g=G, x=x, y=y, k=k, gcd_k=math.gcd(k, P - 1), k_inv=k_inv, r=r, s=s,
                left=left, right=right, valid=(left == right), valid_fake=(left_fake == right))


# ---------------------------------------------------------------------------
def main() -> None:
    msg_path = HERE / "message_lab2.txt"
    data = msg_path.read_bytes()
    fake = data.replace(b"Friedman", b"Fridman", 1)      # mesaj modificat (1 literă)
    h_hex, h = hash_message(data)
    hf_hex, hf = hash_message(fake)

    print("=" * 72)
    print("  LAB 6 — Funcții hash și semnături digitale  (Strunga Daniel-Ioan, FAF-242)")
    print("=" * 72)
    print(f"  k = {K_STUDENT}  ->  i = (k mod 24) + 1 = {HASH_INDEX}  ->  HAVAL-224,4")
    print(f"  Mesajul m: {msg_path.name}, {len(data)} octeți (UTF-8)")
    print(f"  HAVAL-224,4(m) hex = {h_hex}")
    print(f"  HAVAL-224,4(m) dec = {h}   ({h.bit_length()} biți)")
    print(f"  HAVAL-224,4(m') pentru mesajul modificat = {hf_hex}")

    rsa = rsa_signature(h, hf)
    print("\n--- Sarcina 2: semnătura RSA ----------------------------------------")
    for key in ("p", "q", "n", "n_bits", "phi", "e", "d", "s", "h_check"):
        print(f"  {key:<8}= {rsa[key]}")
    print(f"  s^e mod n == h      : {rsa['valid']}   (semnătură validă)")
    print(f"  s^e mod n == h(m')  : {rsa['valid_fake']}  (mesaj modificat respins)")

    eg = elgamal_signature(h, hf)
    print("\n--- Sarcina 3: semnătura ElGamal ------------------------------------")
    for key in ("x", "y", "k", "gcd_k", "k_inv", "r", "s", "left", "right"):
        print(f"  {key:<8}= {eg[key]}")
    print(f"  g^h == y^r * r^s (mod p)     : {eg['valid']}   (semnătură validă)")
    print(f"  g^h(m') == y^r * r^s (mod p) : {eg['valid_fake']}  (mesaj modificat respins)")

    if "--save" in sys.argv:
        out = {"k": K_STUDENT, "hash_index": HASH_INDEX, "msg_len": len(data),
               "h_hex": h_hex, "h": h, "h_bits": h.bit_length(), "hf_hex": hf_hex, "hf": hf,
               "rsa": rsa, "elgamal": eg}
        (HERE / "results.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
        print("\n  Rezultatele au fost salvate în results.json")


if __name__ == "__main__":
    main()
