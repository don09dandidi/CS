# Lucrarea de laborator nr. 4 — Cifruri bloc. Algoritmul DES

**Sarcina 2.11** (n = 22 → 22 mod 11 = 0 → sarcina 11): fiind date `L16` și `R16`, se determină blocul criptat `C = IP⁻¹(R16 ‖ L16)` în hex. Programul afișează tabelul IP⁻¹ și proveniența fiecărui bit.

```bash
python3 des_task_2_11.py                                  # meniu interactiv
python3 des_task_2_11.py --values 942CA100 48F295CB       # L16, R16 în hex
python3 des_task_2_11.py --random                         # L16, R16 aleatorii
python3 des_task_2_11.py --from-message "Strunga " "FAF-242!"   # 16 runde + verificare
```

La pornire rulează un autotest pe vectorii cunoscuți (Grabbe: `85E813540F0AB405`, FIPS 81: `3FA40E8A984D4815`). Rezultatul exemplului din raport (`0D11A4619438519D`) coincide cu `openssl enc -des-ecb`.
