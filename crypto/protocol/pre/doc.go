// Package pre provides generic trusted proxy re-encryption envelopes.
//
// The reference implementation uses secp256k1 ECIES to wrap data keys and
// AES-GCM to encrypt payloads. The proxy in this model is trusted to unwrap the
// delegated data key before re-wrapping it for another recipient.
package pre
