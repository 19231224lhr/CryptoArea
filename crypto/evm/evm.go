package evm

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/19231224lhr/CryptoArea/crypto/hash/sha3"
	"github.com/19231224lhr/CryptoArea/crypto/signature/secp256k1"
)

const personalSignPrefix = "\x19Ethereum Signed Message:\n"

func Keccak256(parts ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		hasher.Write(part)
	}
	sum := hasher.Sum(nil)
	out := make([]byte, len(sum))
	copy(out, sum)
	return out
}

func PersonalSignHash(message []byte) []byte {
	return Keccak256([]byte(personalSignPrefix), []byte(strconv.Itoa(len(message))), message)
}

func PublicKeyToAddress(publicKey []byte) (string, error) {
	uncompressed, err := secp256k1.NormalizePublicKey(publicKey, secp256k1.PublicKeyUncompressed)
	if err != nil {
		return "", err
	}
	if len(uncompressed) != secp256k1.PublicKeyUncompressedBytesLen {
		return "", fmt.Errorf("invalid uncompressed public key length: got %d want %d", len(uncompressed), secp256k1.PublicKeyUncompressedBytesLen)
	}
	sum := Keccak256(uncompressed[1:])
	return "0x" + hex.EncodeToString(sum[len(sum)-20:]), nil
}

func CompactSignatureToSignature65(signatureCompact []byte) ([]byte, error) {
	if len(signatureCompact) != secp256k1.CompactSignatureBytesLen {
		return nil, fmt.Errorf("invalid compact signature length: got %d want %d", len(signatureCompact), secp256k1.CompactSignatureBytesLen)
	}
	out := make([]byte, 65)
	copy(out[:64], signatureCompact[1:])
	out[64] = signatureCompact[0]
	return out, nil
}

func Signature65ToCompact(signature []byte) ([]byte, error) {
	if len(signature) != 65 {
		return nil, fmt.Errorf("invalid 65-byte signature length: got %d want 65", len(signature))
	}
	v := signature[64]
	switch {
	case v <= 3:
		v += 27
	case v >= 27 && v <= 30:
	default:
		return nil, fmt.Errorf("unsupported recovery id: %d", v)
	}
	out := make([]byte, secp256k1.CompactSignatureBytesLen)
	out[0] = v
	copy(out[1:], signature[:64])
	return out, nil
}

func RecoverAddressFromPersonalSign(message []byte, signature []byte) (string, error) {
	compactSignature, err := Signature65ToCompact(signature)
	if err != nil {
		return "", err
	}
	publicKey, err := secp256k1.RecoverPublicKey(PersonalSignHash(message), compactSignature, secp256k1.PublicKeyUncompressed)
	if err != nil {
		return "", err
	}
	return PublicKeyToAddress(publicKey)
}

func VerifyPersonalSignAddress(message []byte, signature []byte, address string) (bool, error) {
	recoveredAddress, err := RecoverAddressFromPersonalSign(message, signature)
	if err != nil {
		return false, err
	}
	normalizedExpected, err := normalizeAddress(address)
	if err != nil {
		return false, err
	}
	return recoveredAddress == normalizedExpected, nil
}

func Bytes32Hex(input []byte) (string, error) {
	if len(input) > 32 {
		return "", fmt.Errorf("input too large for bytes32: got %d want <= 32", len(input))
	}
	out := make([]byte, 32)
	copy(out[32-len(input):], input)
	return "0x" + hex.EncodeToString(out), nil
}

func normalizeAddress(address string) (string, error) {
	normalized := strings.TrimSpace(strings.ToLower(address))
	if normalized == "" {
		return "", fmt.Errorf("address must not be empty")
	}
	normalized = strings.TrimPrefix(normalized, "0x")
	if len(normalized) != 40 {
		return "", fmt.Errorf("invalid address length: got %d want 40", len(normalized))
	}
	if _, err := hex.DecodeString(normalized); err != nil {
		return "", err
	}
	return "0x" + normalized, nil
}
