# Lucrarea de Laborator Nr. 1: Cifrul Caesar și Caesar cu Permutare

Proiect realizat în cadrul cursului de **Securitatea Informațională / Criptografie**, Facultatea Calculatoare, Informatică și Microelectronică, UTM.

## 📌 Descriere

Această lucrare implementează două variante ale cifrului cu substituție monoalfabetică adaptate strict pentru **alfabetul limbii române** ($n = 31$ caractere):

1. **Sarcina 1.1:** Cifrul Caesar clasic (deplasare ciclică simplă cu cheia $k \in \{1, \dots, 30\}$).
2. **Sarcina 1.2:** Cifrul Caesar cu două chei (alfabet permutat generat pe baza unui cuvânt-cheie $k_2$ de minimum 7 litere și deplasare modulară $k_1$).

## ⚙️ Reguli și Constrângeri Tehnice

* **Alfabetul utilizat ($n=31$):** `A Ă Â B C D E F G H I Î J K L M N O P Q R S Ș T Ț U V W X Y Z`
* **Fără ASCII/Unicode:** Nu se utilizează `ord()` sau `chr()` pentru deplasare; indexarea se face exclusiv pe baza tabelei alfabetului.
* **Normalizare automată:** Literele cu sedilă (`Ş`, `Ţ`) sunt convertite automat în litere cu virgulă dedesubt (`Ș`, `Ț`), textul devine majusculă, iar spațiile sunt eliminate.
* **Validare robustă:** Cheile invalide ($k \notin [1, 30]$), cuvintele-cheie prea scurte ($< 7$ caractere) sau simbolurile nepermise sunt respinse cu mesaje de eroare explicite.

## 📁 Structura Proiectului

```text
├── caesar_cipher.py        # Codul sursă complet în Python 3
└── README.md               # Prezentarea generală a proiectului
```

## 🚀 Rulare și Utilizare

Pentru a lansa aplicația în terminal:

```bash
python3 caesar_cipher.py
```

### Exemplu de test (Sarcina 1.1):
* **Cheie ($k$):** `3`
* **Mesaj clar:** `cifrul lui cezar`
* **Criptotext rezultat:** `FKITOXOXKFHÂBT`

### Exemplu de test (Sarcina 1.2):
* **Cheie 1 ($k_1$):** `3`
* **Cuvânt-cheie ($k_2$):** `CRIPTOGRAFIE`
* **Mesaj clar:** `cifrul lui cezar`
* **Criptotext rezultat:** `POÂTXQQXOPĂZAT`

## 🔒 Securitate și Concluzii

* **Caesar Clasic:** Spațiu infim de doar 30 de chei posibile $\rightarrow$ vulnerabil instant la atac prin forță brută.
* **Caesar Permutat:** Mărește spațiul cheilor la peste $2.47 \times 10^{35}$ combinații teoretice, eliminând căutarea exhaustivă neghidată, dar rămâne vulnerabil la **analiza frecvențelor** literelor și digramelor specifice limbii române.