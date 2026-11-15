#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lucrarea de laborator nr. 5: Criptografia cu chei publice

  Sarcina 2.1  RSA (n >= 2048 biți): generarea cheilor, criptarea și decriptarea
               mesajului m = "Strunga Daniel"
  Sarcina 2.2  ElGamal (p de 2048 biți dat, g = 2): generarea cheilor, criptarea
               și decriptarea aceluiași mesaj
  Sarcina 3    Schimbul de chei Diffie-Hellman între Alisa și Bob pentru o cheie
               AES de 256 de biți (același p, g = 2)

Toate calculele folosesc doar aritmetica întregilor din Python (echivalentele
funcțiilor Wolfram RandomPrime, RandomInteger, PowerMod, Mod sunt indicate în
comentarii). Fișierul `wolfram/lab5.wl` conține aceiași pași în Wolfram Language.

Autor: Strunga Daniel-Ioan, gr. FAF-242
Repository: https://github.com/don09dandidi/CS
"""

import hashlib
import math
import json
import secrets
import sys
from pathlib import Path

MESSAGE = "Strunga Daniel"          # m = Nume Prenume

# p (2048 biți) și generatorul g = 2, date în enunț
# (este primul sigur „ffdhe2048” din RFC 7919: p = 2q + 1 cu q prim)
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
assert P.bit_length() == 2048
G = 2


# ---------------------------------------------------------------------------
# Teoria numerelor
# ---------------------------------------------------------------------------
SMALL_PRIMES = [p for p in range(3, 2000) if all(p % q for q in range(2, int(p ** 0.5) + 1))]


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Testul Miller–Rabin (probabilitate de eroare < 4^-40)."""
    if n < 2:
        return False
    for q in [2] + SMALL_PRIMES:
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
    """Echivalent RandomPrime[{2^(bits-1), 2^bits - 1}] cu cei doi biți superiori setați,
    astfel încât produsul a două astfel de numere are exact 2*bits biți."""
    while True:
        cand = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if is_probable_prime(cand):
            return cand


def modinv(a: int, n: int) -> int:
    """Inversul modular a^-1 mod n (algoritmul lui Euclid extins, echivalent
    PowerMod[a, -1, n] în Wolfram)."""
    return pow(a, -1, n)


def random_in(lo: int, hi: int) -> int:
    """Întreg aleator uniform în [lo, hi] (echivalent RandomInteger[{lo, hi}])."""
    return lo + secrets.randbelow(hi - lo + 1)


# ---------------------------------------------------------------------------
# Codificarea mesajului: caractere -> hex ASCII -> număr zecimal
# ---------------------------------------------------------------------------
def encode_message(msg: str):
    hex_str = msg.encode("ascii").hex().upper()
    return hex_str, int(hex_str, 16)


def decode_message(m: int) -> str:
    return bytes.fromhex(format(m, "x").zfill((m.bit_length() + 7) // 8 * 2)).decode("ascii")


# ---------------------------------------------------------------------------
# Sarcina 2.1 — RSA
# ---------------------------------------------------------------------------
def rsa_task(m: int) -> dict:
    p = random_prime(1024)
    q = random_prime(1024)
    while q == p:
        q = random_prime(1024)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    assert math.gcd(e, phi) == 1
    d = modinv(e, phi)
    assert m < n
    c = pow(m, e, n)            # PowerMod[m, e, n]
    m2 = pow(c, d, n)           # PowerMod[c, d, n]
    return dict(p=p, q=q, n=n, n_bits=n.bit_length(), phi=phi, e=e, d=d,
                check_ed=(e * d) % phi, c=c, m_decrypted=m2, ok=(m2 == m))


# ---------------------------------------------------------------------------
# Sarcina 2.2 — ElGamal
# ---------------------------------------------------------------------------
def elgamal_task(m: int) -> dict:
    assert m < P
    x = random_in(2, P - 2)             # cheia privată (Alisa)
    y = pow(G, x, P)                    # cheia publică  y = g^x mod p
    k = random_in(2, P - 2)             # cheie efemeră (Bob), unică pentru fiecare mesaj
    c1 = pow(G, k, P)                   # a = g^k mod p
    c2 = (m * pow(y, k, P)) % P         # b = m * y^k mod p
    s = pow(c1, x, P)                   # secretul comun g^(kx)
    m2 = (c2 * pow(c1, P - 1 - x, P)) % P   # m = b * a^(p-1-x) mod p
    return dict(p=P, g=G, x=x, y=y, k=k, c1=c1, c2=c2, s=s,
                s_inv=modinv(s, P), m_decrypted=m2, ok=(m2 == m))


# ---------------------------------------------------------------------------
# Sarcina 3 — Diffie–Hellman + cheie AES-256
# ---------------------------------------------------------------------------
def dh_task() -> dict:
    a = random_in(2, P - 2)             # secretul Alisei
    b = random_in(2, P - 2)             # secretul lui Bob
    A = pow(G, a, P)                    # Alisa -> Bob
    B = pow(G, b, P)                    # Bob -> Alisa
    k_alice = pow(B, a, P)              # K = B^a mod p
    k_bob = pow(A, b, P)                # K = A^b mod p
    k_bytes = k_alice.to_bytes(256, "big")
    aes_key = hashlib.sha256(k_bytes).hexdigest().upper()   # derivarea cheii de 256 biți
    res = dict(a=a, b=b, A=A, B=B, K_alice=k_alice, K_bob=k_bob, equal=(k_alice == k_bob),
               aes_key_hex=aes_key, aes_key_bits=len(aes_key) * 4)
    res.update(aes_demo(bytes.fromhex(aes_key)))
    return res


def aes_demo(key: bytes) -> dict:
    """Demonstrație opțională: Alisa criptează un mesaj cu AES-256-GCM, Bob îl decriptează."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError:
        return {"aes_demo": "pachetul 'cryptography' nu este instalat (pip install cryptography)"}
    nonce = secrets.token_bytes(12)
    pt = MESSAGE.encode()
    ct = AESGCM(key).encrypt(nonce, pt, None)
    back = AESGCM(key).decrypt(nonce, ct, None)
    return {"aes_nonce": nonce.hex().upper(), "aes_ciphertext": ct.hex().upper(),
            "aes_decrypted": back.decode()}


# ---------------------------------------------------------------------------
def main() -> None:
    hex_str, m = encode_message(MESSAGE)
    print("=" * 72)
    print("  LAB 5 — RSA, ElGamal, Diffie-Hellman   (Strunga Daniel-Ioan, FAF-242)")
    print("=" * 72)
    print(f"\n  Mesajul m = '{MESSAGE}'")
    print(f"  ASCII hex = {hex_str}")
    print(f"  Zecimal   = {m}   ({m.bit_length()} biți)")

    rsa = rsa_task(m)
    print("\n--- Sarcina 2.1: RSA ------------------------------------------------")
    for key in ("p", "q", "n", "n_bits", "phi", "e", "d", "check_ed", "c", "m_decrypted"):
        print(f"  {key:<12}= {rsa[key]}")
    print(f"  Mesaj decriptat: '{decode_message(rsa['m_decrypted'])}'  (corect: {rsa['ok']})")

    eg = elgamal_task(m)
    print("\n--- Sarcina 2.2: ElGamal --------------------------------------------")
    print(f"  p are {P.bit_length()} biți, g = {G}")
    for key in ("x", "y", "k", "c1", "c2", "m_decrypted"):
        print(f"  {key:<12}= {eg[key]}")
    print(f"  Mesaj decriptat: '{decode_message(eg['m_decrypted'])}'  (corect: {eg['ok']})")

    dh = dh_task()
    print("\n--- Sarcina 3: Diffie-Hellman ---------------------------------------")
    for key in ("a", "b", "A", "B", "K_alice", "K_bob", "equal", "aes_key_hex", "aes_key_bits"):
        print(f"  {key:<12}= {dh[key]}")
    for key in ("aes_nonce", "aes_ciphertext", "aes_decrypted", "aes_demo"):
        if key in dh:
            print(f"  {key:<14}= {dh[key]}")

    if "--save" in sys.argv:
        out = {"message": MESSAGE, "hex": hex_str, "m": m, "rsa": rsa, "elgamal": eg, "dh": dh}
        Path(__file__).with_name("results.json").write_text(
            json.dumps(out, indent=2, default=str), encoding="utf-8")
        print("\n  Rezultatele au fost salvate în results.json")


if __name__ == "__main__":
    main()
