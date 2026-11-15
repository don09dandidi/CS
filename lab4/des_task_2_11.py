#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lucrarea de laborator nr. 4: Cifruri bloc. Algoritmul DES
Sarcina 2.11 (n = 22 -> 22 mod 11 = 0 -> sarcina 11):

    La criptarea unui bloc în cifrul DES s-a obţinut L16 și R16 (câte 32 biți).
    Să se determine blocul criptat al mesajului, reprezentat hexazecimal.

    C = IP^-1( R16 || L16 )

Programul afișează tabelele utilizate și toți pașii intermediari. Datele de
intrare pot fi introduse de utilizator, generate aleatoriu sau obținute prin
rularea celor 16 runde DES pe un mesaj + cheie (pentru verificare).

Autor: Strunga Daniel-Ioan, gr. FAF-242
Repository: https://github.com/don09dandidi/CS
"""

import secrets
import sys

# ---------------------------------------------------------------------------
# Tabelele DES (FIPS 46-3)
# ---------------------------------------------------------------------------
IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

IP_INV = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]


# ---------------------------------------------------------------------------
# Funcții auxiliare pe șiruri de biți ('0'/'1')
# ---------------------------------------------------------------------------
def hex_to_bits(h: str, nbits: int) -> str:
    return bin(int(h, 16))[2:].zfill(nbits)


def bits_to_hex(b: str) -> str:
    return hex(int(b, 2))[2:].upper().zfill(len(b) // 4)


def permute(bits: str, table) -> str:
    return "".join(bits[i - 1] for i in table)


def xor(a: str, b: str) -> str:
    return "".join('1' if x != y else '0' for x, y in zip(a, b))


def rotl(bits: str, n: int) -> str:
    return bits[n:] + bits[:n]


def group(bits: str, size: int = 8) -> str:
    return " ".join(bits[i:i + size] for i in range(0, len(bits), size))


def print_table(name: str, table, cols: int = 8) -> None:
    print(f"\n  Tabelul {name} ({len(table)} poziții):")
    for i in range(0, len(table), cols):
        print("    " + "".join(f"{v:>4}" for v in table[i:i + cols]))


# ---------------------------------------------------------------------------
# DES complet (necesar doar pentru a genera/verifica L16 și R16)
# ---------------------------------------------------------------------------
def round_keys(key64: str):
    kplus = permute(key64, PC1)
    c, d = kplus[:28], kplus[28:]
    keys = []
    for s in SHIFTS:
        c, d = rotl(c, s), rotl(d, s)
        keys.append(permute(c + d, PC2))
    return keys


def feistel(r: str, k: str) -> str:
    x = xor(permute(r, E), k)
    out = ""
    for j in range(8):
        b = x[6 * j:6 * j + 6]
        row = int(b[0] + b[5], 2)
        col = int(b[1:5], 2)
        out += format(S_BOXES[j][row][col], "04b")
    return permute(out, P)


def des_rounds(block64: str, key64: str):
    """Returnează (L16, R16) pentru blocul dat, după IP și 16 runde."""
    ip = permute(block64, IP)
    l, r = ip[:32], ip[32:]
    for k in round_keys(key64):
        l, r = r, xor(l, feistel(r, k))
    return l, r


def des_encrypt_block(block64: str, key64: str) -> str:
    l16, r16 = des_rounds(block64, key64)
    return permute(r16 + l16, IP_INV)


# ---------------------------------------------------------------------------
# Sarcina 2.11
# ---------------------------------------------------------------------------
def task_2_11(l16: str, r16: str, verbose: bool = True) -> str:
    assert len(l16) == 32 and len(r16) == 32
    if verbose:
        print("\n" + "=" * 72)
        print("  SARCINA 2.11:  C = IP^-1( R16 || L16 )")
        print("=" * 72)
        print(f"\n  Pasul 0. Datele de intrare")
        print(f"    L16 = {group(l16)}   (hex {bits_to_hex(l16)})")
        print(f"    R16 = {group(r16)}   (hex {bits_to_hex(r16)})")
        print("\n  Pasul 1. După runda 16 jumătățile NU se mai interschimbă,")
        print("           deci blocul de ieșire este R16L16 (64 biți):")
    pre = r16 + l16
    if verbose:
        print(f"    R16L16 = {group(pre)}")
        print("    Poziții (1..64):")
        for i in range(0, 64, 16):
            print("      " + " ".join(f"{i + j + 1:>2}:{pre[i + j]}" for j in range(16)))
        print_table("IP^-1 (permutarea finală)", IP_INV)
        print("\n  Pasul 2. Aplicăm IP^-1: bitul i al ieșirii = bitul IP^-1[i] din R16L16")
    out = permute(pre, IP_INV)
    if verbose:
        for i in range(64):
            if i % 8 == 0:
                print(f"    Octetul {i // 8 + 1}:", end="")
            print(f"  c{i + 1:<2}=b{IP_INV[i]:<2}={out[i]}", end="")
            if i % 8 == 7:
                print(f"   -> {out[i - 7:i + 1]} = {bits_to_hex(out[i - 7:i + 1])}")
        print(f"\n  Pasul 3. Rezultatul")
        print(f"    C (binar) = {group(out)}")
        print(f"    C (hex)   = {bits_to_hex(out)}")
    return bits_to_hex(out)


def read_half(name: str) -> str:
    while True:
        raw = input(f"  {name} (8 cifre hex sau 32 biți): ").strip().replace(" ", "")
        if len(raw) == 32 and set(raw) <= {"0", "1"}:
            return raw
        if len(raw) == 8 and all(c in "0123456789abcdefABCDEF" for c in raw):
            return hex_to_bits(raw, 32)
        print("  [EROARE] Introduceți exact 8 cifre hexazecimale sau 32 de biți 0/1.")


def text_block(text: str) -> str:
    data = text.encode("latin-1", errors="replace")[:8].ljust(8, b"\x00")
    return "".join(format(b, "08b") for b in data)


def selftest() -> None:
    """Vectorul de test clasic (J. Orlin Grabbe, 'The DES Algorithm Illustrated')."""
    m = hex_to_bits("0123456789ABCDEF", 64)
    k = hex_to_bits("133457799BBCDFF1", 64)
    l16, r16 = des_rounds(m, k)
    assert bits_to_hex(l16) == "43423234" and bits_to_hex(r16) == "0A4CD995"
    assert task_2_11(l16, r16, verbose=False) == "85E813540F0AB405"
    # Vector FIPS 81 / NBS: "Now is t" cu cheia 0123456789ABCDEF
    assert bits_to_hex(des_encrypt_block(text_block("Now is t"),
                                         hex_to_bits("0123456789ABCDEF", 64))) == "3FA40E8A984D4815"
    print("  [OK] Autotest DES: vectorii de test cunoscuți sunt reproduși corect.")


def main() -> None:
    print("=" * 72)
    print("  LAB 4 — DES, sarcina 2.11   (Strunga Daniel-Ioan, FAF-242)")
    print("=" * 72)
    selftest()
    args = sys.argv[1:]
    if args[:1] == ["--random"]:
        l16, r16 = format(secrets.randbits(32), "032b"), format(secrets.randbits(32), "032b")
        print("\n  Mod: L16 și R16 generate aleatoriu.")
        task_2_11(l16, r16)
        return
    if args[:1] == ["--values"] and len(args) == 3:
        task_2_11(hex_to_bits(args[1], 32), hex_to_bits(args[2], 32))
        return
    if args[:1] == ["--from-message"] and len(args) == 3:
        run_from_message(args[1], args[2])
        return

    print("\n  1) Introduc L16 și R16 manual")
    print("  2) Generez L16 și R16 aleatoriu")
    print("  3) Calculez L16, R16 din mesaj (8 caractere) + cheie (8 caractere) și verific")
    choice = input("  Opțiunea: ").strip()
    if choice == "1":
        task_2_11(read_half("L16"), read_half("R16"))
    elif choice == "2":
        task_2_11(format(secrets.randbits(32), "032b"), format(secrets.randbits(32), "032b"))
    elif choice == "3":
        run_from_message(input("  Mesaj (8 caractere): "), input("  Cheie (8 caractere): "))
    else:
        print("  [EROARE] Opțiune invalidă.")


def run_from_message(msg: str, key: str) -> None:
    m, k = text_block(msg), text_block(key)
    print(f"\n  Mesaj '{msg[:8]}' -> hex {bits_to_hex(m)};  cheie '{key[:8]}' -> hex {bits_to_hex(k)}")
    l16, r16 = des_rounds(m, k)
    c = task_2_11(l16, r16)
    full = bits_to_hex(des_encrypt_block(m, k))
    print(f"\n  Verificare cu DES complet: {full}  ->  {'CORECT' if full == c else 'GREȘIT'}")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print()
