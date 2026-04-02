package walletcrypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestSeedChainDeterministicRecovery(t *testing.T) {
	root := []byte("seedchain-deterministic-root")

	sc1, err := NewSeedChainFromSeed(AlgECDSA, root, 4)
	if err != nil {
		t.Fatalf("NewSeedChainFromSeed failed: %v", err)
	}
	sc2, err := NewSeedChainFromSeed(AlgECDSA, root, 4)
	if err != nil {
		t.Fatalf("NewSeedChainFromSeed second call failed: %v", err)
	}

	anchor1, err := sc1.CurrentAnchor()
	if err != nil {
		t.Fatalf("CurrentAnchor failed: %v", err)
	}
	anchor2, err := sc2.CurrentAnchor()
	if err != nil {
		t.Fatalf("CurrentAnchor second call failed: %v", err)
	}
	if !bytes.Equal(anchor1, anchor2) {
		t.Fatal("expected identical current anchors for identical root seeds")
	}

	kp1, err := sc1.DeriveCurrentKeyPair()
	if err != nil {
		t.Fatalf("DeriveCurrentKeyPair failed: %v", err)
	}
	kp2, err := sc2.DeriveCurrentKeyPair()
	if err != nil {
		t.Fatalf("DeriveCurrentKeyPair second call failed: %v", err)
	}
	if !bytes.Equal(kp1.PublicKey, kp2.PublicKey) || !bytes.Equal(kp1.PrivateKey, kp2.PrivateKey) {
		t.Fatal("expected identical deterministic key pairs at the same step")
	}
}

func TestSeedChainConsumeAndRecover(t *testing.T) {
	root := []byte("seedchain-recover-root")

	sc, err := NewSeedChainFromSeed(AlgECDSA, root, 5)
	if err != nil {
		t.Fatalf("NewSeedChainFromSeed failed: %v", err)
	}

	seed, kp, step, nextAnchor, err := sc.ConsumeSeed()
	if err != nil {
		t.Fatalf("ConsumeSeed failed: %v", err)
	}
	if step != 5 {
		t.Fatalf("unexpected consumed step: got %d want 5", step)
	}
	if len(seed) == 0 || kp == nil || len(kp.PublicKey) == 0 {
		t.Fatal("ConsumeSeed returned incomplete signing material")
	}
	if sc.RemainingSteps() != 4 {
		t.Fatalf("unexpected remaining steps: got %d want 4", sc.RemainingSteps())
	}

	expectedNextAnchor, err := sc.AnchorAtStep(4)
	if err != nil {
		t.Fatalf("AnchorAtStep failed: %v", err)
	}
	if !bytes.Equal(nextAnchor, expectedNextAnchor) {
		t.Fatal("next anchor mismatch after consume")
	}

	recovered, err := RecoverSeedChain(AlgECDSA, root, 5, 4)
	if err != nil {
		t.Fatalf("RecoverSeedChain failed: %v", err)
	}
	recoveredKP, err := recovered.DeriveCurrentKeyPair()
	if err != nil {
		t.Fatalf("recovered DeriveCurrentKeyPair failed: %v", err)
	}
	currentKP, err := sc.DeriveCurrentKeyPair()
	if err != nil {
		t.Fatalf("current DeriveCurrentKeyPair failed: %v", err)
	}
	if !bytes.Equal(recoveredKP.PublicKey, currentKP.PublicKey) || !bytes.Equal(recoveredKP.PrivateKey, currentKP.PrivateKey) {
		t.Fatal("recovered chain does not match the original chain state")
	}
}

func TestSeedChainExhaustion(t *testing.T) {
	sc, err := NewSeedChainFromSeed(AlgECDSA, []byte("seedchain-exhaust-root"), 1)
	if err != nil {
		t.Fatalf("NewSeedChainFromSeed failed: %v", err)
	}

	if _, _, _, _, err := sc.ConsumeSeed(); err != nil {
		t.Fatalf("first ConsumeSeed failed unexpectedly: %v", err)
	}
	if _, _, _, _, err := sc.ConsumeSeed(); !errors.Is(err, ErrSeedChainExhausted) {
		t.Fatalf("expected ErrSeedChainExhausted, got %v", err)
	}
}
