package pqcgo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type KeyPair struct {
	Scheme     int
	PublicKey  []byte
	PrivateKey []byte
}

func ParseSchemeName(name string) (int, error) {
	scheme, ok := PQCSignType[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return -1, fmt.Errorf("unsupported scheme name: %s", name)
	}
	return scheme, nil
}

func GenerateKeyPair(scheme int) (*KeyPair, error) {
	if err := validateWalletScheme(scheme); err != nil {
		return nil, err
	}

	pk, sk, err := KeyGen(scheme)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Scheme:     scheme,
		PublicKey:  pk,
		PrivateKey: sk,
	}, nil
}

func GenerateKeyPairWithSeed(scheme int, seed []byte) (*KeyPair, error) {
	if err := validateWalletScheme(scheme); err != nil {
		return nil, err
	}
	if len(seed) == 0 {
		return nil, fmt.Errorf("seed must not be empty")
	}

	pk, sk, err := KeyGenWithSeed(scheme, seed)
	if err != nil {
		return nil, err
	}
	return &KeyPair{
		Scheme:     scheme,
		PublicKey:  pk,
		PrivateKey: sk,
	}, nil
}

func SignMessage(scheme int, message []byte, privateKey []byte) ([]byte, error) {
	if err := validateWalletScheme(scheme); err != nil {
		return nil, err
	}
	return Sign(scheme, message, privateKey)
}

func VerifyMessage(scheme int, signature []byte, message []byte, publicKey []byte) (bool, error) {
	if err := validateWalletScheme(scheme); err != nil {
		return false, err
	}
	return Verify(scheme, signature, message, publicKey)
}

func GenerateAddress(scheme int, publicKey []byte, opts *AddressOptions) (string, error) {
	if err := validateWalletScheme(scheme); err != nil {
		return "", err
	}
	if len(publicKey) != PUBLICKEYBYTES[scheme] {
		return "", fmt.Errorf("invalid public key length: got %d want %d", len(publicKey), PUBLICKEYBYTES[scheme])
	}

	normalized, err := normalizeAddressOptions(opts)
	if err != nil {
		return "", err
	}
	payload, err := publicKeyToAddressPayload(publicKey, normalized.HashLength)
	if err != nil {
		return "", err
	}
	return encodeAddress(payload, normalized)
}

func PublicKeyFingerprint(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:8])
}

func HashSHA256(data []byte) []byte {
	sum := sha256.Sum256(data)
	out := make([]byte, sha256.Size)
	copy(out, sum[:])
	return out
}

func HMACSHA256(key []byte, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

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

func validateWalletScheme(scheme int) error {
	if scheme < 0 || scheme >= len(PUBLICKEYBYTES) {
		return fmt.Errorf("invalid scheme: %d", scheme)
	}
	return nil
}
