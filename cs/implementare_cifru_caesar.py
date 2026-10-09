#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Lucrarea de laborator nr. 1: Cifrul Caesar și Cifrul Caesar cu Permutare
Descriere: Implementarea cifrului Caesar clasic și cu alfabet permutat
           pentru limba română (n = 31 caractere).
"""

import sys

# Tabelul 2: Codificarea caracterelor alfabetului limbii române (n = 31)
ROMANIAN_ALPHABET = [
    'A', 'Ă', 'Â', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'Î', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'Ș', 'T', 'Ț', 'U', 'V', 'W', 'X', 'Y', 'Z'
]
N = len(ROMANIAN_ALPHABET)  # 31

# Tabele de corespondență explicită (fără coduri ASCII/Unicode pentru deplasare)
CHAR_TO_CODE = {char: idx for idx, char in enumerate(ROMANIAN_ALPHABET)}
CODE_TO_CHAR = {idx: char for idx, char in enumerate(ROMANIAN_ALPHABET)}


def normalize_text(text: str) -> str:
    """
    Normalizează textul introdus:
    1. Înlocuiește variantele cu sedilă (Ş, Ţ) cu virgule dedesubt (Ș, Ț).
    2. Convertește caracterele la majuscule.
    3. Elimină spațiile libere.
    """
    text = text.replace('Ş', 'Ș').replace('ş', 'ș')
    text = text.replace('Ţ', 'Ț').replace('ţ', 'ț')
    text = text.upper()
    text = text.replace(' ', '')
    return text


def validate_text(text: str) -> tuple[bool, str]:
    """
    Verifică dacă toate caracterele din text aparțin alfabetului limbii române.
    Returnează (True, "") dacă este valid, sau (False, primul_caracter_invalid).
    """
    for char in text:
        if char not in CHAR_TO_CODE:
            return False, char
    return True, ""


def get_valid_key() -> int:
    """
    Citește și validează cheia numerică k din consolă.
    Intervalul permis: 1 <= k <= 30.
    """
    while True:
        raw = input("Introduceți cheia numerică k (număr întreg între 1 și 30): ").strip()
        try:
            k = int(raw)
            if 1 <= k <= (N - 1):
                return k
            else:
                print(f"[EROARE] Cheia {k} este în afara intervalului permis! Introduceți o valoare între 1 și 30.")
        except ValueError:
            print("[EROARE] Valoarea introdusă nu este un număr întreg valid!")


def get_valid_message(prompt: str) -> str:
    """
    Citește un mesaj de la tastatură, îl normalizează și îl validează.
    În caz de caractere nepermise, afișează eroarea și solicită reintroducerea.
    """
    while True:
        raw = input(prompt)
        normalized = normalize_text(raw)
        if not normalized:
            print("[EROARE] Textul nu poate fi gol!")
            continue

        valid, invalid_char = validate_text(normalized)
        if valid:
            return normalized
        else:
            print(f"[EROARE] Caracterul nepermis '{invalid_char}' a fost respins!")
            print("Sunt acceptate doar litere din alfabetul român (A-Z, Ă, Â, Î, Ș, Ț).")


def get_valid_keyword() -> str:
    """
    Citește și validează cuvântul-cheie pentru Sarcina 1.2:
    - conține doar litere din alfabetul român;
    - lungimea minimă este de 7 caractere.
    """
    while True:
        raw = input("Introduceți cuvântul-cheie k2 (minim 7 litere): ")
        normalized = normalize_text(raw)
        if len(normalized) < 7:
            print(f"[EROARE] Cuvântul-cheie are doar {len(normalized)} caractere. Lungimea minimă permisă este 7!")
            continue

        valid, invalid_char = validate_text(normalized)
        if valid:
            return normalized
        else:
            print(f"[EROARE] Caracterul '{invalid_char}' din cuvântul-cheie este invalid!")


# ==============================================================================
# Sarcina 1.1: Cifrul Caesar clasic
# ==============================================================================

def caesar_encrypt(plaintext: str, k: int) -> str:
    """Criptează textul folosind formula: c = (x + k) mod 31"""
    ciphertext_chars = []
    for char in plaintext:
        x = CHAR_TO_CODE[char]
        c = (x + k) % N
        ciphertext_chars.append(CODE_TO_CHAR[c])
    return "".join(ciphertext_chars)


def caesar_decrypt(ciphertext: str, k: int) -> str:
    """Decriptează textul folosind formula: m = (y - k) mod 31"""
    plaintext_chars = []
    for char in ciphertext:
        y = CHAR_TO_CODE[char]
        m = (y - k) % N
        plaintext_chars.append(CODE_TO_CHAR[m])
    return "".join(plaintext_chars)


# ==============================================================================
# Sarcina 1.2: Cifrul Caesar cu două chei (Permutare)
# ==============================================================================

def build_permuted_alphabet(keyword: str) -> list[str]:
    """
    Construiește alfabetul permutat pe baza cuvântului-cheie:
    1. Literele unice din cuvântul-cheie în ordinea apariției.
    2. Literele rămase din alfabetul standard în ordinea lor naturală.
    """
    permuted = []
    seen = set()

    for char in keyword:
        if char not in seen:
            permuted.append(char)
            seen.add(char)

    for char in ROMANIAN_ALPHABET:
        if char not in seen:
            permuted.append(char)
            seen.add(char)

    return permuted


def permuted_caesar_encrypt(plaintext: str, k1: int, permuted_alphabet: list[str]) -> str:
    """Criptează pe baza alfabetului permutat: c = (x + k1) mod 31"""
    perm_char_to_code = {char: idx for idx, char in enumerate(permuted_alphabet)}
    ciphertext_chars = []
    for char in plaintext:
        x = perm_char_to_code[char]
        c = (x + k1) % N
        ciphertext_chars.append(permuted_alphabet[c])
    return "".join(ciphertext_chars)


def permuted_caesar_decrypt(ciphertext: str, k1: int, permuted_alphabet: list[str]) -> str:
    """Decriptează pe baza alfabetului permutat: m = (y - k1) mod 31"""
    perm_char_to_code = {char: idx for idx, char in enumerate(permuted_alphabet)}
    plaintext_chars = []
    for char in ciphertext:
        y = perm_char_to_code[char]
        m = (y - k1) % N
        plaintext_chars.append(permuted_alphabet[m])
    return "".join(plaintext_chars)


# ==============================================================================
# Interfața utilizator (CLI)
# ==============================================================================

def run_task_1():
    print("\n--- Sarcina 1.1: Cifrul Caesar clasic peste alfabetul român ---")
    print("1. Criptare")
    print("2. Decriptare")
    op = input("Alegeți operația (1 sau 2): ").strip()
    if op not in ['1', '2']:
        print("[EROARE] Opțiune invalidă!")
        return

    k = get_valid_key()
    if op == '1':
        msg = get_valid_message("Introduceți mesajul clar: ")
        res = caesar_encrypt(msg, k)
        print(f"\n[REZULTAT] Text procesat : {msg}")
        print(f"[REZULTAT] Text criptat  : {res}")
    else:
        ctx = get_valid_message("Introduceți criptotextul: ")
        res = caesar_decrypt(ctx, k)
        print(f"\n[REZULTAT] Criptotext procesat: {ctx}")
        print(f"[REZULTAT] Text decriptat     : {res}")


def run_task_2():
    print("\n--- Sarcina 1.2: Cifrul Caesar cu două chei (cu permutare) ---")
    print("1. Criptare")
    print("2. Decriptare")
    op = input("Alegeți operația (1 sau 2): ").strip()
    if op not in ['1', '2']:
        print("[EROARE] Opțiune invalidă!")
        return

    k1 = get_valid_key()
    k2 = get_valid_keyword()

    permuted = build_permuted_alphabet(k2)
    print("\nAlfabetul permutat generat (verificare vizuală):")
    print("".join(f"{ch:>2} " for ch in permuted))
    print("".join(f"{i:>2} " for i in range(N)))

    if op == '1':
        msg = get_valid_message("Introduceți mesajul clar: ")
        res = permuted_caesar_encrypt(msg, k1, permuted)
        print(f"\n[REZULTAT] Text procesat : {msg}")
        print(f"[REZULTAT] Text criptat  : {res}")
    else:
        ctx = get_valid_message("Introduceți criptotextul: ")
        res = permuted_caesar_decrypt(ctx, k1, permuted)
        print(f"\n[REZULTAT] Criptotext procesat: {ctx}")
        print(f"[REZULTAT] Text decriptat     : {res}")


def main():
    while True:
        print("\n" + "=" * 60)
        print(" LABORATORUL NR. 1: CIFRUL CAESAR (ALFABETUL ROMÂN)")
        print("=" * 60)
        print("1. Execută Sarcina 1.1 (Cifrul Caesar simplu)")
        print("2. Execută Sarcina 1.2 (Cifrul Caesar cu două chei)")
        print("3. Ieșire")
        choice = input("Selectați o opțiune (1-3): ").strip()

        if choice == '1':
            run_task_1()
        elif choice == '2':
            run_task_2()
        elif choice == '3':
            print("Programul s-a încheiat.")
            sys.exit(0)
        else:
            print("[EROARE] Opțiune necunoscută! Reîncercați.")


if __name__ == "__main__":
    main()