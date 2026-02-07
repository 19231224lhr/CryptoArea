package walletcrypto

import (
	"blockchain-crypto/hash/ripemd160"
	"blockchain-crypto/hash/sha3"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"strings"
)

func RandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid random length: %d", length)
	}
	out := make([]byte, length)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func HashData(algorithm string, data []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(algorithm)) {
	case "sha256":
		sum := sha256.Sum256(data)
		return sum[:], nil
	case "sha512":
		sum := sha512.Sum512(data)
		return sum[:], nil
	case "keccak256":
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		return h.Sum(nil), nil
	case "ripemd160":
		h := ripemd160.New()
		h.Write(data)
		return h.Sum(nil), nil
	case "hash160":
		return hash160(data), nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

func HMACSHA256(key []byte, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}
