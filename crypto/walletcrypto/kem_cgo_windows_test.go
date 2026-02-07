//go:build cgo && windows

package walletcrypto

import (
	"bytes"
	"testing"
)

func TestKEMRoundTrip(t *testing.T) {
	algorithms := []string{AlgPQMLKEM768, AlgPQAigisEnc1}
	for _, algorithm := range algorithms {
		keyPair, err := GenerateKEMKeyPair(algorithm)
		if err != nil {
			t.Fatalf("GenerateKEMKeyPair(%s) failed: %v", algorithm, err)
		}

		ct, ss1, err := EncapsulateSharedSecret(algorithm, keyPair.PublicKey)
		if err != nil {
			t.Fatalf("EncapsulateSharedSecret(%s) failed: %v", algorithm, err)
		}
		ss2, err := DecapsulateSharedSecret(algorithm, keyPair.PrivateKey, ct)
		if err != nil {
			t.Fatalf("DecapsulateSharedSecret(%s) failed: %v", algorithm, err)
		}
		if !bytes.Equal(ss1, ss2) {
			t.Fatalf("shared secret mismatch for %s", algorithm)
		}
	}
}

func TestKEMWrongPrivateKeyProducesDifferentSecret(t *testing.T) {
	keyA, err := GenerateKEMKeyPair(AlgPQMLKEM768)
	if err != nil {
		t.Fatalf("GenerateKEMKeyPair A failed: %v", err)
	}
	keyB, err := GenerateKEMKeyPair(AlgPQMLKEM768)
	if err != nil {
		t.Fatalf("GenerateKEMKeyPair B failed: %v", err)
	}

	ct, ss1, err := EncapsulateSharedSecret(AlgPQMLKEM768, keyA.PublicKey)
	if err != nil {
		t.Fatalf("EncapsulateSharedSecret failed: %v", err)
	}
	ss2, err := DecapsulateSharedSecret(AlgPQMLKEM768, keyB.PrivateKey, ct)
	if err != nil {
		t.Fatalf("DecapsulateSharedSecret failed: %v", err)
	}
	if bytes.Equal(ss1, ss2) {
		t.Fatal("expected different shared secrets when using wrong private key")
	}
}

func TestKEMInvalidInputs(t *testing.T) {
	if _, err := GenerateKEMKeyPair("unknown_kem"); err == nil {
		t.Fatal("expected GenerateKEMKeyPair to fail")
	}
	if _, _, err := EncapsulateSharedSecret(AlgPQMLKEM768, nil); err == nil {
		t.Fatal("expected EncapsulateSharedSecret to fail with nil public key")
	}
	if _, err := DecapsulateSharedSecret(AlgPQMLKEM768, nil, []byte{1}); err == nil {
		t.Fatal("expected DecapsulateSharedSecret to fail with nil private key")
	}
}
