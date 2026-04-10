// Package walletcrypto provides a stable wallet-oriented crypto facade over
// classical signature algorithms, post-quantum signature algorithms, KEM,
// address generation, keystore helpers, common hashes, and deterministic
// seed-chain utilities.
//
// Recommended usage:
//   - Use GenerateKeyPair / GenerateKeyPairWithSeed for key creation
//   - Use SignMessage / VerifyMessage for signing flows
//   - Use GenerateAddress for address derivation
//   - Use NewSeedChain / RecoverSeedChain when you need deterministic
//     one-time-key workflows driven by a hash chain
//
// Important boundary notes:
//   - AlgECDSA currently resolves to secp256k1
//   - The package is not an EVM personal_sign compatibility layer
//   - For EVM-facing hashing, address recovery, and signature checks, use
//     github.com/19231224lhr/CryptoArea/crypto/evm
//   - For stable structured-data canonicalization, use
//     github.com/19231224lhr/CryptoArea/crypto/encoding/canonical
//
// The package intentionally keeps business protocol concerns out of the API so
// upper-layer projects can compose their own wallet, transaction, or state
// models on top.
package walletcrypto
