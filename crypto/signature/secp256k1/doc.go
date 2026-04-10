// Package secp256k1 exposes explicit secp256k1 signing and recovery helpers.
//
// It exists to separate raw secp256k1/ECDSA behavior from higher-level facades
// such as walletcrypto, and to provide a stable building block for EVM-related
// compatibility helpers.
package secp256k1
