# Laboratory Work No. 5 — PKI and Digital Signatures (OpenSSL)

Internal PKI implemented in Bash on top of `openssl`:

* CA: RSA 4096, self-signed certificate valid 3650 days
* users: RSA ≥ 2048, certificates valid 365 days, issued and revoked by the CA (CRL)
* signing files with RSA/SHA-256 and verifying them (certificate chain + CRL + signature)

```bash
./pki.sh demo                 # full scenario (issue, sign, verify, tamper, revoke)
./pki.sh init-ca
./pki.sh issue daniel
./pki.sh sign daniel file.pdf
./pki.sh verify daniel file.pdf
./pki.sh revoke daniel keyCompromise
./pki.sh list
```

The generated `pki/` directory contains private keys and is git-ignored.
