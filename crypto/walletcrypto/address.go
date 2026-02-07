package walletcrypto

import (
	"blockchain-crypto/hash/ripemd160"
	"blockchain-crypto/hash/sha3"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

func GenerateAddress(publicKey []byte, opts *AddressOptions) (string, error) {
	if len(publicKey) == 0 {
		return "", fmt.Errorf("public key must not be empty")
	}

	normalized := AddressOptions{
		Format:  AddressFormatBase58Check,
		Version: 0x00,
	}
	if opts != nil {
		if opts.Format != "" {
			normalized.Format = opts.Format
		}
		normalized.Version = opts.Version
	}

	switch normalized.Format {
	case AddressFormatBase58Check:
		payload := hash160(publicKey)
		versioned := make([]byte, 1+len(payload))
		versioned[0] = normalized.Version
		copy(versioned[1:], payload)
		return base58CheckEncode(versioned), nil
	case AddressFormatHash160Hex:
		return hex.EncodeToString(hash160(publicKey)), nil
	case AddressFormatEthereumHex:
		h := sha3.NewLegacyKeccak256()
		h.Write(publicKey)
		sum := h.Sum(nil)
		if len(sum) < 20 {
			return "", fmt.Errorf("invalid keccak output length")
		}
		return "0x" + hex.EncodeToString(sum[len(sum)-20:]), nil
	default:
		return "", fmt.Errorf("unsupported address format: %s", normalized.Format)
	}
}

func hash160(data []byte) []byte {
	first := sha256.Sum256(data)
	r := ripemd160.New()
	r.Write(first[:])
	return r.Sum(nil)
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

	value := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	remainder := new(big.Int)
	out := make([]byte, 0, len(input))

	for value.Sign() > 0 {
		value.DivMod(value, base, remainder)
		out = append(out, base58Alphabet[int(remainder.Int64())])
	}

	for _, b := range input {
		if b != 0x00 {
			break
		}
		out = append(out, base58Alphabet[0])
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}
