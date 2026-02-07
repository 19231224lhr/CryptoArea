package walletcrypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateKeyPairAndSignVerifyClassical(t *testing.T) {
	keyPair, err := GenerateKeyPair(AlgECDSA)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(keyPair.PrivateKey) == 0 || len(keyPair.PublicKey) == 0 {
		t.Fatal("GenerateKeyPair returned empty key bytes")
	}

	message := []byte("walletcrypto-message")
	sig, err := SignMessage(AlgECDSA, keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	ok, err := VerifyMessage(AlgECDSA, keyPair.PublicKey, message, sig)
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyMessage returned false")
	}
}

func TestGenerateAddressProfiles(t *testing.T) {
	keyPair, err := GenerateKeyPair(AlgEdDSA)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	base58Addr, err := GenerateAddress(keyPair.PublicKey, &AddressOptions{
		Format:  AddressFormatBase58Check,
		Version: 0x00,
	})
	if err != nil {
		t.Fatalf("GenerateAddress base58 failed: %v", err)
	}
	if base58Addr == "" {
		t.Fatal("GenerateAddress base58 returned empty value")
	}

	hexAddr, err := GenerateAddress(keyPair.PublicKey, &AddressOptions{
		Format: AddressFormatHash160Hex,
	})
	if err != nil {
		t.Fatalf("GenerateAddress hex failed: %v", err)
	}
	if len(hexAddr) != 40 {
		t.Fatalf("unexpected hash160 hex length: %d", len(hexAddr))
	}

	ethAddr, err := GenerateAddress(keyPair.PublicKey, &AddressOptions{
		Format: AddressFormatEthereumHex,
	})
	if err != nil {
		t.Fatalf("GenerateAddress ethereum failed: %v", err)
	}
	if !strings.HasPrefix(ethAddr, "0x") || len(ethAddr) != 42 {
		t.Fatalf("unexpected ethereum address: %s", ethAddr)
	}
}

func TestHashHMACAndKeystore(t *testing.T) {
	hash, err := HashData("hash160", []byte("abc"))
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	if len(hash) != 20 {
		t.Fatalf("unexpected hash length: %d", len(hash))
	}

	mac := HMACSHA256([]byte("k"), []byte("abc"))
	if len(mac) != 32 {
		t.Fatalf("unexpected hmac length: %d", len(mac))
	}

	encrypted, err := EncryptPrivateKey([]byte("secret-key"), []byte("pass"))
	if err != nil {
		t.Fatalf("EncryptPrivateKey failed: %v", err)
	}
	decrypted, err := DecryptPrivateKey(encrypted, []byte("pass"))
	if err != nil {
		t.Fatalf("DecryptPrivateKey failed: %v", err)
	}
	if !bytes.Equal(decrypted, []byte("secret-key")) {
		t.Fatal("DecryptPrivateKey returned wrong plaintext")
	}

	if _, err := DecryptPrivateKey(encrypted, []byte("wrong")); err == nil {
		t.Fatal("expected DecryptPrivateKey to fail with wrong passphrase")
	}
}

func TestInvalidInputs(t *testing.T) {
	if _, err := GenerateKeyPair("unknown-alg"); err == nil {
		t.Fatal("expected GenerateKeyPair to return error")
	}
	if _, err := SignMessage(AlgSM2, nil, []byte("m")); err == nil {
		t.Fatal("expected SignMessage to return error")
	}
	if _, err := GenerateAddress(nil, nil); err == nil {
		t.Fatal("expected GenerateAddress to return error")
	}
	if _, err := HashData("unknown-hash", []byte("m")); err == nil {
		t.Fatal("expected HashData to return error")
	}
	if _, err := EncryptPrivateKey(nil, []byte("pass")); err == nil {
		t.Fatal("expected EncryptPrivateKey to return error")
	}
}
