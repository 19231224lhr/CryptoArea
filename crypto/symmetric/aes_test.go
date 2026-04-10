package symmetric

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAESGCMRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	nonce := []byte("0123456789ab")
	plaintext := []byte("hello symmetric crypto")
	aad := []byte("aad")

	ciphertext, err := AESGCMEncrypt(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("AESGCMEncrypt failed: %v", err)
	}
	roundTrip, err := AESGCMDecrypt(key, nonce, ciphertext, aad)
	if err != nil {
		t.Fatalf("AESGCMDecrypt failed: %v", err)
	}
	if !bytes.Equal(roundTrip, plaintext) {
		t.Fatal("AES GCM round-trip mismatch")
	}
}

func TestAESOFBBytesAndFileRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	iv := []byte("0123456789abcdef")
	plaintext := []byte("hello ofb")

	ciphertext, err := AESOFBEncrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("AESOFBEncrypt failed: %v", err)
	}
	roundTrip, err := AESOFBDecrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("AESOFBDecrypt failed: %v", err)
	}
	if !bytes.Equal(roundTrip, plaintext) {
		t.Fatal("AES OFB byte round-trip mismatch")
	}

	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.bin")
	encryptedPath := filepath.Join(tempDir, "encrypted.bin")
	decryptedPath := filepath.Join(tempDir, "decrypted.bin")

	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := AESOFBEncryptFile(key, iv, inputPath, encryptedPath); err != nil {
		t.Fatalf("AESOFBEncryptFile failed: %v", err)
	}
	if err := AESOFBDecryptFile(key, iv, encryptedPath, decryptedPath); err != nil {
		t.Fatalf("AESOFBDecryptFile failed: %v", err)
	}
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatal("AES OFB file round-trip mismatch")
	}
}
