(* ::Package:: *)
(* Lucrarea de laborator nr. 5 - Criptografia cu chei publice
   Strunga Daniel-Ioan, FAF-242
   Same steps as public_key_crypto.py, written in Wolfram Language
   (Wolfram Mathematica / Wolfram Cloud). *)

(* ---------- Encoding of the message: characters -> ASCII hex -> decimal ---------- *)
msg = "Strunga Daniel";
hex = StringJoin[IntegerString[ToCharacterCode[msg], 16, 2]];
m = FromDigits[hex, 16]
decode[x_] := FromCharacterCode[IntegerDigits[x, 256]];

(* ---------- Task 2.1: RSA, n >= 2048 bits ---------- *)
p = RandomPrime[{2^1023 + 2^1022, 2^1024 - 1}];
q = RandomPrime[{2^1023 + 2^1022, 2^1024 - 1}];
n = p*q;
BitLength[n]                     (* 2048 *)
phi = (p - 1)*(q - 1);
e = 65537;
GCD[e, phi]                      (* must be 1 *)
d = PowerMod[e, -1, phi];        (* d = e^-1 mod phi(n) *)
Mod[e*d, phi]                    (* check: 1 *)
c = PowerMod[m, e, n]            (* encryption  c = m^e mod n *)
mRSA = PowerMod[c, d, n]         (* decryption  m = c^d mod n *)
decode[mRSA]

(* ---------- common parameters for 2.2 and 3 ---------- *)
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
{BitLength[P], PrimeQ[P], PrimeQ[(P - 1)/2]}   (* {2048, True, True} *)

(* ---------- Task 2.2: ElGamal ---------- *)
x = RandomInteger[{2, P - 2}];   (* private key *)
y = PowerMod[g, x, P];           (* public key y = g^x mod p *)
k = RandomInteger[{2, P - 2}];   (* ephemeral key, new for every message *)
c1 = PowerMod[g, k, P];          (* c1 = g^k mod p *)
c2 = Mod[m*PowerMod[y, k, P], P];(* c2 = m*y^k mod p *)
mEG = Mod[c2*PowerMod[c1, P - 1 - x, P], P]   (* m = c2 * c1^(p-1-x) mod p *)
decode[mEG]

(* ---------- Task 3: Diffie-Hellman for an AES-256 key ---------- *)
a = RandomInteger[{2, P - 2}];   (* Alice's secret *)
b = RandomInteger[{2, P - 2}];   (* Bob's secret *)
A = PowerMod[g, a, P];           (* Alice -> Bob *)
B = PowerMod[g, b, P];           (* Bob -> Alice *)
KA = PowerMod[B, a, P];
KB = PowerMod[A, b, P];
KA == KB                         (* True *)
(* 256-bit AES key = SHA-256 of the 256-byte big-endian representation of K *)
aesKey = Hash[ByteArray[IntegerDigits[KA, 256, 256]], "SHA256", "HexString"]
