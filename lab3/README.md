# Lucrarea de laborator nr. 3 — Cifruri polialfabetice (Vigenère)

**Sarcina 3.2** (număr de ordine 22, par): cifrul Vigenère pentru limba română, alfabet de 31 de litere codificate 0…30.

* `c_i = (m_i + k_i) mod 31`, `m_i = (c_i − k_i) mod 31`
* spațiile se elimină, textul devine majusculă, Ş/Ţ cu sedilă → Ș/Ț
* sunt permise doar literele A–Z, a–z și Ă Â Î Ș Ț; altfel programul afișează diapazonul corect
* cheia are minim 7 litere

```bash
python3 vigenere_ro.py          # meniu interactiv: criptare / decriptare
python3 vigenere_ro.py --demo   # exemplele din raport
```

| Fișier | Conținut |
|---|---|
| `vigenere_ro.py` | implementarea |
| `demo_output.txt` | ieșirea modului `--demo` |
| `raport_lab3.tex` / `.pdf` | raportul |
