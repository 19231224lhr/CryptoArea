# walletcrypto

中文文档请见：[`README_CN.md`](./README_CN.md)

`walletcrypto` is a unified wallet-facing crypto package built on top of:
- `crypto/signature` (classical signatures)
- `pqcgo` (post-quantum signatures)

It provides:
- key generation (`GenerateKeyPair`, `GenerateKeyPairWithSeed`)
- signing/verification (`SignMessage`, `VerifyMessage`)
- post-quantum KEM (`GenerateKEMKeyPair`, `EncapsulateSharedSecret`, `DecapsulateSharedSecret`)
- address generation (`GenerateAddress`)
- utility primitives (`RandomBytes`, `HashData`, `HMACSHA256`)
- private key encryption/decryption (`EncryptPrivateKey`, `DecryptPrivateKey`)

## Supported Algorithms

Classical:
- `bls`
- `ecdsa`
- `ec_schnorr`
- `eddsa`
- `eddsa_cosmos`
- `sm2`

Post-Quantum:
- `pq_aigis_sig`
- `pq_dilithium`
- `pq_ml_dsa`
- `pq_slh_dsa`

Post-Quantum KEM:
- `pq_ml_kem_512`
- `pq_ml_kem_768`
- `pq_ml_kem_1024`
- `pq_aigis_enc_1`
- `pq_aigis_enc_2`
- `pq_aigis_enc_3`
- `pq_aigis_enc_4`
