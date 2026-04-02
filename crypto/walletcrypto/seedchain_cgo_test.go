//go:build cgo

package walletcrypto

import (
	"bytes"
	"testing"
)

func TestSeedChainSupportsPQAlgorithms(t *testing.T) {
	sc, err := NewSeedChainFromSeed(AlgPQMLDSA, []byte("seedchain-pq-root"), 3)
	if err != nil {
		t.Fatalf("NewSeedChainFromSeed failed: %v", err)
	}

	kp, err := sc.DeriveCurrentKeyPair()
	if err != nil {
		t.Fatalf("DeriveCurrentKeyPair failed: %v", err)
	}

	message := []byte("seedchain-pq-signing-message")
	sig, err := SignMessage(AlgPQMLDSA, kp.PrivateKey, message)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}
	ok, err := VerifyMessage(AlgPQMLDSA, kp.PublicKey, message, sig)
	if err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}
	if !ok {
		t.Fatal("expected pq verification to succeed")
	}

	seed, _, step, nextAnchor, err := sc.ConsumeSeed()
	if err != nil {
		t.Fatalf("ConsumeSeed failed: %v", err)
	}
	if step != 3 {
		t.Fatalf("unexpected consumed step: got %d want 3", step)
	}
	expectedNextAnchor, err := sc.AnchorAtStep(2)
	if err != nil {
		t.Fatalf("AnchorAtStep failed: %v", err)
	}
	if !bytes.Equal(nextAnchor, expectedNextAnchor) {
		t.Fatal("pq next anchor mismatch")
	}
	if len(seed) == 0 {
		t.Fatal("expected seed reveal bytes")
	}
}
