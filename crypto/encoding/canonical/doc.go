// Package canonical provides deterministic JSON canonicalization helpers.
//
// The package is intended to give callers one stable JSON encoding surface for
// hashing, signing, and cross-language verification. Legacy behaviors that need
// to differ should be expressed through explicit wrapper packages or profiles.
package canonical
