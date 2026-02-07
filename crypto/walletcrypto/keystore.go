package walletcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const (
	keystoreVersion    byte = 0x01
	keystoreSaltLen         = 16
	keystoreNonceLen        = 12
	keystoreKeyLen          = 32
	keystorePBKDF2Iter      = 100000
)

func EncryptPrivateKey(privateKey []byte, passphrase []byte) ([]byte, error) {
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("private key must not be empty")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}

	salt := make([]byte, keystoreSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key := pbkdf2.Key(passphrase, salt, keystorePBKDF2Iter, keystoreKeyLen, sha256.New)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, keystoreNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, privateKey, nil)

	out := make([]byte, 1+keystoreSaltLen+keystoreNonceLen+len(ciphertext))
	out[0] = keystoreVersion
	copy(out[1:], salt)
	copy(out[1+keystoreSaltLen:], nonce)
	copy(out[1+keystoreSaltLen+keystoreNonceLen:], ciphertext)
	return out, nil
}

func DecryptPrivateKey(payload []byte, passphrase []byte) ([]byte, error) {
	minLen := 1 + keystoreSaltLen + keystoreNonceLen + 1
	if len(payload) < minLen {
		return nil, fmt.Errorf("invalid payload length")
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}
	if payload[0] != keystoreVersion {
		return nil, fmt.Errorf("unsupported keystore version: %d", payload[0])
	}

	saltStart := 1
	nonceStart := saltStart + keystoreSaltLen
	cipherStart := nonceStart + keystoreNonceLen

	salt := payload[saltStart:nonceStart]
	nonce := payload[nonceStart:cipherStart]
	ciphertext := payload[cipherStart:]

	key := pbkdf2.Key(passphrase, salt, keystorePBKDF2Iter, keystoreKeyLen, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
	}
	return plain, nil
}
