//go:build !cgo

package walletcrypto

import (
	"strings"
	"testing"
)

func TestPQCNoCGOReturnsExpectedError(t *testing.T) {
	_, err := GenerateKeyPair(AlgPQMLDSA)
	if err == nil {
		t.Fatal("expected GenerateKeyPair to return error")
	}
	if !strings.Contains(err.Error(), "requires cgo") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = GenerateKEMKeyPair(AlgPQMLKEM768)
	if err == nil {
		t.Fatal("expected GenerateKEMKeyPair to return error")
	}
	if !strings.Contains(err.Error(), "requires cgo") {
		t.Fatalf("unexpected error: %v", err)
	}
}
