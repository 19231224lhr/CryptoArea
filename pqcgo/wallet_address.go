package pqcgo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

type AddressEncoding string

const (
	AddressEncodingHex         AddressEncoding = "hex"
	AddressEncodingBase58Check AddressEncoding = "base58check"
)

type AddressOptions struct {
	Encoding   AddressEncoding
	Version    byte
	HashLength int
}

const defaultAddressHashLength = 20

func normalizeAddressOptions(opts *AddressOptions) (AddressOptions, error) {
	if opts == nil {
		return AddressOptions{
			Encoding:   AddressEncodingBase58Check,
			Version:    0x00,
			HashLength: defaultAddressHashLength,
		}, nil
	}

	normalized := *opts
	if normalized.Encoding == "" {
		normalized.Encoding = AddressEncodingBase58Check
	}
	if normalized.HashLength == 0 {
		normalized.HashLength = defaultAddressHashLength
	}
	if normalized.HashLength < 1 || normalized.HashLength > sha256.Size {
		return AddressOptions{}, fmt.Errorf("invalid hash length: %d", normalized.HashLength)
	}
	if normalized.Encoding != AddressEncodingHex && normalized.Encoding != AddressEncodingBase58Check {
		return AddressOptions{}, fmt.Errorf("unsupported address encoding: %s", normalized.Encoding)
	}

	return normalized, nil
}

func publicKeyToAddressPayload(publicKey []byte, hashLength int) ([]byte, error) {
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("public key must not be empty")
	}
	if hashLength < 1 || hashLength > sha256.Size {
		return nil, fmt.Errorf("invalid hash length: %d", hashLength)
	}

	sum := sha256.Sum256(publicKey)
	out := make([]byte, hashLength)
	copy(out, sum[:hashLength])
	return out, nil
}

func encodeAddress(payload []byte, opts AddressOptions) (string, error) {
	switch opts.Encoding {
	case AddressEncodingHex:
		return hex.EncodeToString(payload), nil
	case AddressEncodingBase58Check:
		versioned := make([]byte, 1+len(payload))
		versioned[0] = opts.Version
		copy(versioned[1:], payload)
		return base58CheckEncode(versioned), nil
	default:
		return "", fmt.Errorf("unsupported address encoding: %s", opts.Encoding)
	}
}

func base58CheckEncode(payload []byte) string {
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	encoded := make([]byte, len(payload)+4)
	copy(encoded, payload)
	copy(encoded[len(payload):], second[:4])
	return base58Encode(encoded)
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	x := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	rem := new(big.Int)

	result := make([]byte, 0, len(input))
	for x.Sign() > 0 {
		x.DivMod(x, base, rem)
		result = append(result, base58Alphabet[int(rem.Int64())])
	}

	for _, b := range input {
		if b != 0x00 {
			break
		}
		result = append(result, base58Alphabet[0])
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}
