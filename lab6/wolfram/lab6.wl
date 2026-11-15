(* ::Package:: *)
(* Lucrarea de laborator nr. 6 - Functii hash si semnaturi digitale
   Strunga Daniel-Ioan, FAF-242.  k = 22 -> i = (22 mod 24) + 1 = 23 -> HAVAL-224,4
   Wolfram's Hash[] does not implement HAVAL, so the digest of the message from
   Lab 2 (file message_lab2.txt) is computed with haval.py / PHP hash("haval224,4", ...)
   and converted from hexadecimal to decimal, as the guide recommends. *)

hHex = "699A7B65152794B3D652C28987E742E25767CAE4DBDDA1F7096E118A";
h = FromDigits[hHex, 16]          (* = 11121340838540799761581205197693366182088800469145110944605870625162 *)

(* ---------- Task 2: RSA signature, n >= 3072 bits ---------- *)
p = RandomPrime[{2^1535 + 2^1534, 2^1536 - 1}];
q = RandomPrime[{2^1535 + 2^1534, 2^1536 - 1}];
n = p*q;
BitLength[n]                     (* 3072 *)
phi = (p - 1)*(q - 1);
e = 65537;
GCD[e, phi]                      (* 1 *)
d = PowerMod[e, -1, phi];
s = PowerMod[h, d, n]            (* signature s = h^d mod n *)
PowerMod[s, e, n] == h           (* verification: True *)

(* ---------- Task 3: ElGamal signature ---------- *)
P = FromDigits[StringJoin[
  "3231700607131100730015351347782516336248805713348907517458843413",
  "9269806834136210002792056362640164685458556357935330816928829023",
  "0805734726252735547424612457410262025279165729728627063003252634",
  "2821314576693141422365422094111134862999165747826803423055308634",
  "9050635557712219187890332729569696129743856241741236237225197346",
  "4026918557977679768230146253979330580152268587307611975324364674",
  "7585546071504389684494036613049769781285429595865959756705128385",
  "2132784468522925504568272879113720098931873959143374175837826000",
  "2780349731985520606075332341226032546840881200311059074842810039",
  "94966956119696956248629032338072839127039"
]];
g = 2;
x = RandomInteger[{2, P - 2}];          (* private key *)
y = PowerMod[g, x, P];                  (* public key *)
k = RandomInteger[{2, P - 2}];
While[GCD[k, P - 1] != 1, k = RandomInteger[{2, P - 2}]];
r = PowerMod[g, k, P];                  (* r = g^k mod p *)
s = Mod[(h - x*r)*PowerMod[k, -1, P - 1], P - 1]   (* s = (h - x r) k^-1 mod (p-1) *)
PowerMod[g, h, P] == Mod[PowerMod[y, r, P]*PowerMod[r, s, P], P]   (* True *)
