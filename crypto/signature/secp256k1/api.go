package secp256k1

import (
	"fmt"

	btcec "github.com/19231224lhr/CryptoArea/crypto/signature/ecdsa/dependency"
)

type PublicKeyEncoding string

const (
	PublicKeyCompressed   PublicKeyEncoding = "compressed"
	PublicKeyUncompressed PublicKeyEncoding = "uncompressed"
)

const (
	PrivateKeyBytesLen            = btcec.PrivKeyBytesLen
	PublicKeyCompressedBytesLen   = btcec.PubKeyBytesLenCompressed
	PublicKeyUncompressedBytesLen = btcec.PubKeyBytesLenUncompressed
	CompactSignatureBytesLen      = 65
)

func GenerateKeyPair() ([]byte, []byte, error) {
	privateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, nil, err
	}
	return privateKey.Serialize(), privateKey.PubKey().SerializeCompressed(), nil
}

func GenerateKeyPairWithSeed(seed []byte) ([]byte, []byte, error) {
	if len(seed) == 0 {
		return nil, nil, fmt.Errorf("seed must not be empty")
	}
	privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), seed)
	return privateKey.Serialize(), publicKey.SerializeCompressed(), nil
}

func DerivePublicKey(privateKey []byte, encoding PublicKeyEncoding) ([]byte, error) {
	if err := validatePrivateKey(privateKey); err != nil {
		return nil, err
	}
	derived, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), privateKey)
	_ = derived
	return encodePublicKey(publicKey, encoding)
}

func NormalizePublicKey(publicKey []byte, encoding PublicKeyEncoding) ([]byte, error) {
	parsed, err := btcec.ParsePubKey(publicKey, btcec.S256())
	if err != nil {
		return nil, err
	}
	return encodePublicKey(parsed, encoding)
}

func SignDER(privateKey []byte, digest []byte) ([]byte, error) {
	parsed, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest must not be empty")
	}
	signature, err := parsed.Sign(digest)
	if err != nil {
		return nil, err
	}
	return signature.Serialize(), nil
}

func VerifyDER(publicKey []byte, digest []byte, signatureDER []byte) (bool, error) {
	if len(digest) == 0 {
		return false, fmt.Errorf("digest must not be empty")
	}
	if len(signatureDER) == 0 {
		return false, fmt.Errorf("signature must not be empty")
	}
	parsedPublicKey, err := parsePublicKey(publicKey)
	if err != nil {
		return false, err
	}
	signature, err := btcec.ParseSignature(signatureDER, btcec.S256())
	if err != nil {
		return false, err
	}
	return signature.Verify(digest, parsedPublicKey), nil
}

func SignCompact(privateKey []byte, digest []byte, compressed bool) ([]byte, error) {
	parsed, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest must not be empty")
	}
	signature, err := btcec.SignCompact(btcec.S256(), parsed, digest, compressed)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func RecoverPublicKey(digest []byte, signatureCompact []byte, encoding PublicKeyEncoding) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest must not be empty")
	}
	if len(signatureCompact) != CompactSignatureBytesLen {
		return nil, fmt.Errorf("invalid compact signature length: got %d want %d", len(signatureCompact), CompactSignatureBytesLen)
	}
	publicKey, _, err := btcec.RecoverCompact(btcec.S256(), signatureCompact, digest)
	if err != nil {
		return nil, err
	}
	return encodePublicKey(publicKey, encoding)
}

func ComputeSharedSecret(privateKey []byte, publicKey []byte) ([]byte, error) {
	parsedPrivateKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	parsedPublicKey, err := parsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	secret := btcec.GenerateSharedSecret(parsedPrivateKey, parsedPublicKey)
	out := make([]byte, len(secret))
	copy(out, secret)
	return out, nil
}

func ECIESEncrypt(publicKey []byte, plaintext []byte) ([]byte, error) {
	parsedPublicKey, err := parsePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	ciphertext, err := btcec.Encrypt(parsedPublicKey, plaintext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}

func ECIESDecrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	parsedPrivateKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	plaintext, err := btcec.Decrypt(parsedPrivateKey, ciphertext)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, nil
}

func validatePrivateKey(privateKey []byte) error {
	if len(privateKey) == 0 {
		return fmt.Errorf("private key must not be empty")
	}
	if len(privateKey) != PrivateKeyBytesLen {
		return fmt.Errorf("invalid private key length: got %d want %d", len(privateKey), PrivateKeyBytesLen)
	}
	return nil
}

func parsePrivateKey(privateKey []byte) (*btcec.PrivateKey, error) {
	if err := validatePrivateKey(privateKey); err != nil {
		return nil, err
	}
	parsed, _ := btcec.PrivKeyFromBytes(btcec.S256(), privateKey)
	return parsed, nil
}

func parsePublicKey(publicKey []byte) (*btcec.PublicKey, error) {
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("public key must not be empty")
	}
	return btcec.ParsePubKey(publicKey, btcec.S256())
}

func encodePublicKey(publicKey *btcec.PublicKey, encoding PublicKeyEncoding) ([]byte, error) {
	switch encoding {
	case PublicKeyCompressed:
		return publicKey.SerializeCompressed(), nil
	case PublicKeyUncompressed:
		return publicKey.SerializeUncompressed(), nil
	default:
		return nil, fmt.Errorf("unsupported public key encoding: %s", encoding)
	}
}
