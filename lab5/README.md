# Lucrarea de laborator nr. 5 — Criptografia cu chei publice

* **2.1** RSA cu n de 2048 biți — criptarea/decriptarea mesajului `m = "Strunga Daniel"`
* **2.2** ElGamal cu p (2048 biți, din enunț) și g = 2
* **3** Diffie–Hellman între Alisa și Bob → cheie AES de 256 biți (SHA-256 din secretul comun) + demonstrație AES-256-GCM

```bash
pip install cryptography             # opțional, doar pentru demonstrația AES
python3 public_key_crypto.py --save  # afișează toți pașii, salvează results.json
```

`wolfram/lab5.wl` — aceiași pași în Wolfram Language. Raportul (`raport_lab5.pdf`) se generează din șablon:
`python3 ../common/fill_report.py raport_lab5.tpl.tex results.json raport_lab5.tex && xelatex raport_lab5.tex`
