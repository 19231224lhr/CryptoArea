//go:build cgo

package walletcrypto

import (
	"bytes"
	"testing"
)

func TestPQCGenerateKeyPairAndSignVerify(t *testing.T) {
	keyPair, err := GenerateKeyPair(AlgPQMLDSA)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := []byte{0x01}
	sig, err := SignMessage(AlgPQMLDSA, keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	ok, err := VerifyMessage(AlgPQMLDSA, keyPair.PublicKey, message, sig)
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if !ok {
		t.Fatal("VerifyMessage returned false")
	}
}

func TestPQCKeyGenWithSeedDeterministic(t *testing.T) {
	seed := []byte("walletcrypto-pqc-seed")

	a, err := GenerateKeyPairWithSeed(AlgPQSLHDSA, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithSeed first failed: %v", err)
	}
	b, err := GenerateKeyPairWithSeed(AlgPQSLHDSA, seed)
	if err != nil {
		t.Fatalf("GenerateKeyPairWithSeed second failed: %v", err)
	}

	if !bytes.Equal(a.PrivateKey, b.PrivateKey) || !bytes.Equal(a.PublicKey, b.PublicKey) {
		t.Fatal("GenerateKeyPairWithSeed is not deterministic")
	}
}
