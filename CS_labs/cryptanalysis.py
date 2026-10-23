"""
Laboratory Work No. 2: Cryptanalysis of Monoalphabetic Substitution Ciphers
Course: Cryptography and Information Security
Author: Strunga Daniel-Ioan
Student of group: FAF-242
Repository: https://github.com/don09dandidi/CS
"""

import collections

class DecryptionKey:
def init(self):
self.cipher_to_plain = {}
self.plain_to_cipher = {}

def set_mapping(self, cipher_letter: str, plain_letter: str) -> bool:
    c = cipher_letter.upper()
    p = plain_letter.lower()
    if not ('A' <= c <= 'Z') or not ('a' <= p <= 'z'):
        return False
    
    # Enforce bijectivity by resolving conflicts
    if p in self.plain_to_cipher:
        old_c = self.plain_to_cipher[p]
        if old_c in self.cipher_to_plain:
            del self.cipher_to_plain[old_c]
    if c in self.cipher_to_plain:
        old_p = self.cipher_to_plain[c]
        if old_p in self.plain_to_cipher:
            del self.plain_to_cipher[old_p]
        
    self.cipher_to_plain[c] = p
    self.plain_to_cipher[p] = c
    return True

def remove_mapping(self, cipher_letter: str):
    c = cipher_letter.upper()
    if c in self.cipher_to_plain:
        p = self.cipher_to_plain[c]
        del self.cipher_to_plain[c]
        if p in self.plain_to_cipher:
            del self.plain_to_cipher[p]

def decrypt_text(self, ciphertext: str) -> str:
    result = []
    for char in ciphertext:
        upper_char = char.upper()
        if upper_char in self.cipher_to_plain:
            plain_char = self.cipher_to_plain[upper_char]
            result.append(plain_char.upper() if char.isupper() else plain_char)
        else:
            result.append(char)
    return "".join(result)


class FrequencyAnalyzer:
"""Computes letter occurrence distributions and Index of Coincidence (IC)."""
@staticmethod
def compute_ic(text: str) -> float:
clean = "".join([c for c in text if c.isalpha()]).upper()
total = len(clean)
if total <= 1:
return 0.0
counts = collections.Counter(clean)
numerator = sum(f * (f - 1) for f in counts.values())
denominator = total * (total - 1)
return numerator / denominator

@staticmethod
def get_frequency_table(text: str):
    clean = "".join([c for c in text if c.isalpha()]).upper()
    total = len(clean)
    counts = collections.Counter(clean)
    return total, counts.most_common()


def main():
# Variant 22 Ciphertext dataset
ciphertext_v22 = (
"Rqxsv Qviaviw Ftiosvf ztf av wqv avpw lgnrg hifuwnsnjxpw, dghngwvpwtasf "
"wqv jivtwvpw xp Rxssxtz Civovixhl Cixvoztg. Dgsxlv qxphngwvzunitif, qxp "
"vzxgvghv xp odv znpw vzuqtwxhtssf wn rqtv qv oxo. Xgovvo, wrn zniv "
"oxppxzxsti zvg xg t pxgjsv cxvso htg phtihvsf avxztjxgvo, wxss Otwn "
"jtkv vyuivppxng wn qxp rtiztozxitwxng cni qnpw zvg rqn htg vyusnxw "
"rqativ htssvo 'hxuqvip.'"
)

print("=" * 60)
print(" CRYPTANALYSIS SUITE - VARIANT 22")
print(" Course: Cryptography and Information Security")
print(f" Author: Strunga Daniel-Ioan (Group FAF-242)")
print(f" Repository: https://github.com/don09dandidi/CS")
print("=" * 60)

total_chars, sorted_freqs = FrequencyAnalyzer.get_frequency_table(ciphertext_v22)
ic_val = FrequencyAnalyzer.compute_ic(ciphertext_v22)

print(f"\n[+] Total Alphabetic Characters: {total_chars}")
print(f"[+] Computed Index of Coincidence (IC): {ic_val:.4f} (Expected English ~0.0667)")

print("\n[+] Ciphertext Letter Frequencies:")
for char, count in sorted_freqs:
    percentage = (count / total_chars) * 100
    print(f"    {char}: {count} ({percentage:.2f}%)")

# Initialize key with deduced mappings for Variant 22 (Affine C = 7P + 19 mod 26)
key = DecryptionKey()
mappings = {
    'V': 'e', 'T': 't', 'W': 'a', 'X': 'o',
    'G': 'i', 'N': 'n', 'I': 'r', 'S': 's', 'O': 'd'
}

for cipher_c, plain_c in mappings.items():
    key.set_mapping(cipher_c, plain_c)

print("\n[+] Decrypted Preview with Initial Mappings:")
print("-" * 60)
print(key.decrypt_text(ciphertext_v22))
print("-" * 60)


if name == "main":
main()