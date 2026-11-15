# Lucrarea de laborator nr. 6 — Funcții hash și semnături digitale

k = 22 → i = (22 mod 24) + 1 = 23 → **HAVAL-224,4** (în ambele liste). Mesajul `m` este textul decriptat în lab. 2 (`message_lab2.txt`, UTF-8, 3555 octeți).

* `haval.py` — implementare HAVAL (224/256 biți, 3/4/5 treceri), verificată cu `hash()` din PHP
* `digital_signatures.py` — semnătura RSA (n = 3072 biți) și semnătura ElGamal (p de 2048 biți, g = 2)

```bash
python3 haval.py < message_lab2.txt
# 699a7b65152794b3d652c28987e742e25767cae4dbdda1f7096e118a
python3 digital_signatures.py --save
```

`wolfram/lab6.wl` — aceiași pași în Wolfram Language (Wolfram nu are HAVAL, deci valoarea hash e introdusă în zecimal).
