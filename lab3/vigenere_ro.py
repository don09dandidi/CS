#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lucrarea de laborator nr. 3: Cifruri polialfabetice — Sarcina 3.2
Cifrul Vigenère pentru mesaje în limba română (n = 31 de litere)

Autor: Strunga Daniel-Ioan, gr. FAF-242
Repository: https://github.com/don09dandidi/CS

Model matematic:
    criptare:   c_i = (m_i + k_(i mod |k|)) mod 31
    decriptare: m_i = (c_i - k_(i mod |k|)) mod 31
"""

import sys

# Codificarea alfabetului limbii române: A=0, Ă=1, ..., Z=30
ROMANIAN_ALPHABET = [
    'A', 'Ă', 'Â', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'Î', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'Ș', 'T', 'Ț', 'U', 'V', 'W', 'X', 'Y', 'Z',
]
N = len(ROMANIAN_ALPHABET)  # 31
CHAR_TO_CODE = {ch: i for i, ch in enumerate(ROMANIAN_ALPHABET)}
MIN_KEY_LEN = 7


class InvalidInputError(ValueError):
    """Ridicată când textul sau cheia conțin caractere din afara alfabetului."""


def normalize(text: str) -> str:
    """Unifică diacriticele (Ş/Ţ cu sedilă -> Ș/Ț cu virgulă), elimină spațiile
    și transformă toate literele în majuscule."""
    text = (text.replace('Ş', 'Ș').replace('ş', 'ș')
                .replace('Ţ', 'Ț').replace('ţ', 'ț'))
    text = "".join(text.split())  # elimină spații, tab-uri, linii noi
    return text.upper()


def validate(text: str, what: str = "textul") -> None:
    bad = sorted({ch for ch in text if ch not in CHAR_TO_CODE})
    if bad:
        raise InvalidInputError(
            f"{what.capitalize()} conține caractere nepermise: {' '.join(bad)}\n"
            f"  Diapazonul corect: literele 'A'–'Z', 'a'–'z' și diacriticele "
            f"românești Ă Â Î Ș Ț (31 de litere); spațiile sunt eliminate automat."
        )
    if not text:
        raise InvalidInputError(f"{what.capitalize()} nu poate fi gol.")


def prepare_key(key: str) -> str:
    key = normalize(key)
    validate(key, "cheia")
    if len(key) < MIN_KEY_LEN:
        raise InvalidInputError(
            f"Cheia are {len(key)} litere; lungimea minimă este {MIN_KEY_LEN}.")
    return key


def vigenere(text: str, key: str, decrypt: bool = False, trace: bool = False) -> str:
    """Criptează/decriptează `text` (deja normalizat) cu cheia `key`."""
    sign = -1 if decrypt else 1
    out = []
    rows = []
    for i, ch in enumerate(text):
        m = CHAR_TO_CODE[ch]
        k = CHAR_TO_CODE[key[i % len(key)]]
        c = (m + sign * k) % N
        out.append(ROMANIAN_ALPHABET[c])
        rows.append((ch, key[i % len(key)], m, k, c, ROMANIAN_ALPHABET[c]))
    if trace:
        print_trace(rows, decrypt)
    return "".join(out)


def print_trace(rows, decrypt: bool) -> None:
    """Afișează tabelul de calcul, ca în exemplul din îndrumar (câte 16 coloane)."""
    op = "M–K (mod 31)" if decrypt else "M+K (mod 31)"
    src = "Criptograma C" if decrypt else "Textul clar M"
    dst = "Textul clar M" if decrypt else "Criptograma C"
    for start in range(0, len(rows), 16):
        chunk = rows[start:start + 16]
        lines = [
            (src, [r[0] for r in chunk]),
            ("Cheia K", [r[1] for r in chunk]),
            ("Cod " + src[-1], [str(r[2]) for r in chunk]),
            ("Cod K", [str(r[3]) for r in chunk]),
            (op, [str(r[4]) for r in chunk]),
            (dst, [r[5] for r in chunk]),
        ]
        for label, vals in lines:
            print(f"  {label:<15}" + "".join(f"{v:>4}" for v in vals))
        print()


def print_alphabet() -> None:
    print("  Codificarea alfabetului (n = 31):")
    for start in (0, 16):
        part = ROMANIAN_ALPHABET[start:start + 16]
        print("   " + "".join(f"{c:>4}" for c in part))
        print("   " + "".join(f"{i:>4}" for i in range(start, start + len(part))))


def ask(prompt: str, prep) -> str:
    while True:
        try:
            return prep(input(prompt))
        except InvalidInputError as e:
            print(f"[EROARE] {e}")


def interactive() -> None:
    print("=" * 70)
    print("  LAB 3 — Cifrul Vigenère pentru limba română (31 de litere)")
    print("  Strunga Daniel-Ioan, FAF-242")
    print("=" * 70)
    print_alphabet()
    while True:
        print("\n  1) Criptare   2) Decriptare   0) Ieșire")
        choice = input("  Opțiunea: ").strip()
        if choice == "0":
            return
        if choice not in ("1", "2"):
            print("[EROARE] Alegeți 1, 2 sau 0.")
            continue
        decrypt = choice == "2"
        key = ask(f"  Cheia (minim {MIN_KEY_LEN} litere): ", prepare_key)

        def prep_text(t):
            t = normalize(t)
            validate(t, "criptograma" if decrypt else "mesajul")
            return t

        text = ask("  Criptograma: " if decrypt else "  Mesajul: ", prep_text)
        print(f"\n  Text pregătit : {text}")
        print(f"  Cheia         : {key}\n")
        result = vigenere(text, key, decrypt=decrypt, trace=True)
        print(("  Mesajul decriptat: " if decrypt else "  Criptograma: ") + result)


def demo() -> None:
    """Exemple deterministe folosite în raport."""
    print_alphabet()
    examples = [
        ("Per aspera ad astra", "SUPERMAN"),
        ("Criptografia și securitatea informațională la UTM", "CHIȘINĂU"),
    ]
    for msg, key in examples:
        m, k = normalize(msg), prepare_key(key)
        print(f"\n>>> Criptare: M = '{msg}'  ->  '{m}',  K = '{k}'")
        c = vigenere(m, k, trace=True)
        print(f"    C = {c}")
        print(f">>> Decriptare cu aceeași cheie:")
        d = vigenere(c, k, decrypt=True, trace=False)
        print(f"    M = {d}   (corect: {d == m})")
    print("\n>>> Validare intrări greșite:")
    for bad_key, bad_msg in [("SECRET", "TEST"), ("CHEIELUNGA", "Salut 2026!")]:
        try:
            prepare_key(bad_key)
            validate(normalize(bad_msg), "mesajul")
        except InvalidInputError as e:
            print(f"    [EROARE] {e}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        demo()
    else:
        try:
            interactive()
        except (KeyboardInterrupt, EOFError):
            print()
