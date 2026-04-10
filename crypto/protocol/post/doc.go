// Package post provides a generic, profile-versioned Proof-of-SpaceTime style
// challenge/response transcript service.
//
// The implementation focuses on stable byte-level behavior so callers can keep
// protocol inputs, challenge derivation, proof generation, and verification
// aligned across systems while still choosing between strict and legacy
// compatibility profiles.
package post
