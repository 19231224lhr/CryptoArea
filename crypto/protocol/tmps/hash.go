package tmps

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/19231224lhr/CryptoArea/crypto/hash/sha3"
)

const (
	HashAlgorithmSHA256    = "sha256"
	HashAlgorithmKeccak256 = "keccak256"
)

func HashBytes(algorithm string, payload []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case HashAlgorithmSHA256:
		sum := sha256.Sum256(payload)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	case HashAlgorithmKeccak256:
		hasher := sha3.NewLegacyKeccak256()
		hasher.Write(payload)
		return hasher.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported tmps hash algorithm: %s", algorithm)
	}
}
