//go:build cgo

package pqcgo

import (
	"bytes"
	"testing"
)

func TestParseSchemeName(t *testing.T) {
	tests := map[string]int{
		"aigis_sig": 0,
		"dilithium": 1,
		"ml_dsa":    2,
		"slh_dsa":   3,
	}

	for name, want := range tests {
		got, err := ParseSchemeName(name)
		if err != nil {
			t.Fatalf("ParseSchemeName(%s) returned error: %v", name, err)
		}
		if got != want {
			t.Fatalf("ParseSchemeName(%s) = %d, want %d", name, got, want)
		}
	}
}

func TestGenerateKeyPairSignVerifyAllSchemes(t *testing.T) {
	for scheme := 0; scheme < 4; scheme++ {
		keyPair, err := GenerateKeyPair(scheme)
		if err != nil {
			t.Fatalf("GenerateKeyPair failed for scheme %d: %v", scheme, err)
		}

		msg := []byte("wallet-api-message")
		sig, err := SignMessage(scheme, msg, keyPair.PrivateKey)
		if err != nil {
			t.Fatalf("SignMessage failed for scheme %d: %v", scheme, err)
		}

		ok, err := VerifyMessage(scheme, sig, msg, keyPair.PublicKey)
		if err != nil {
			t.Fatalf("VerifyMessage failed for scheme %d: %v", scheme, err)
		}
		if !ok {
			t.Fatalf("VerifyMessage returned false for scheme %d", scheme)
		}
	}
}

func TestGenerateAddressDeterministic(t *testing.T) {
	keyPair, err := GenerateKeyPair(0)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	opts := &AddressOptions{
		Encoding:   AddressEncodingBase58Check,
		Version:    0x00,
		HashLength: 20,
	}
	addr1, err := GenerateAddress(0, keyPair.PublicKey, opts)
	if err != nil {
		t.Fatalf("GenerateAddress first failed: %v", err)
	}
	addr2, err := GenerateAddress(0, keyPair.PublicKey, opts)
	if err != nil {
		t.Fatalf("GenerateAddress second failed: %v", err)
	}
	if addr1 == "" || addr2 == "" {
		t.Fatal("GenerateAddress returned empty address")
	}
	if addr1 != addr2 {
		t.Fatal("GenerateAddress is not deterministic for same public key")
	}
}

func TestGenerateAddressSupportsHexEncoding(t *testing.T) {
	keyPair, err := GenerateKeyPair(1)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	opts := &AddressOptions{
		Encoding:   AddressEncodingHex,
		HashLength: 20,
	}
	addr, err := GenerateAddress(1, keyPair.PublicKey, opts)
	if err != nil {
		t.Fatalf("GenerateAddress failed: %v", err)
	}
	if len(addr) != 40 {
		t.Fatalf("unexpected hex address length: %d", len(addr))
	}
}

func TestGenerateKeyPairWithSeedDeterministic(t *testing.T) {
	seed := []byte("wallet-seed-001")
	keyPairA, err := GenerateKeyPairWithSeed(3, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithSeed first failed: %v", err)
	}
	keyPairB, err := GenerateKeyPairWithSeed(3, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithSeed second failed: %v", err)
	}
	if !bytes.Equal(keyPairA.PublicKey, keyPairB.PublicKey) || !bytes.Equal(keyPairA.PrivateKey, keyPairB.PrivateKey) {
		t.Fatal("GenerateKeyPairWithSeed is not deterministic")
	}
}

func TestWalletHelpers(t *testing.T) {
	rnd, err := RandomBytes(16)
	if err != nil {
		t.Fatalf("RandomBytes failed: %v", err)
	}
	if len(rnd) != 16 {
		t.Fatalf("unexpected random bytes length: %d", len(rnd))
	}

	hash := HashSHA256([]byte("abc"))
	if len(hash) != 32 {
		t.Fatalf("unexpected hash length: %d", len(hash))
	}

	mac := HMACSHA256([]byte("key"), []byte("abc"))
	if len(mac) != 32 {
		t.Fatalf("unexpected mac length: %d", len(mac))
	}

	fp := PublicKeyFingerprint([]byte("pk"))
	if len(fp) != 16 {
		t.Fatalf("unexpected fingerprint length: %d", len(fp))
	}
}

func TestWalletAPIReturnsErrorOnInvalidInput(t *testing.T) {
	if _, err := ParseSchemeName("unknown"); err == nil {
		t.Fatal("expected ParseSchemeName to return error")
	}

	if _, err := GenerateKeyPair(-1); err == nil {
		t.Fatal("expected GenerateKeyPair to return error")
	}

	if _, err := GenerateKeyPairWithSeed(0, nil); err == nil {
		t.Fatal("expected GenerateKeyPairWithSeed to return error")
	}

	if _, err := RandomBytes(0); err == nil {
		t.Fatal("expected RandomBytes to return error")
	}

	if _, err := GenerateAddress(0, []byte{1, 2, 3}, nil); err == nil {
		t.Fatal("expected GenerateAddress to return error for invalid key length")
	}
}
