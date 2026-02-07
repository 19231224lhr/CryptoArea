//go:build !cgo

package pqcgo

import (
	"strings"
	"testing"
)

func TestWalletAPIWithoutCGO(t *testing.T) {
	checkErr := func(err error) {
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires cgo") {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	keyPair, err := GenerateKeyPair(0)
	if keyPair != nil {
		t.Fatal("expected nil key pair")
	}
	checkErr(err)

	keyPair, err = GenerateKeyPairWithSeed(0, []byte("seed"))
	if keyPair != nil {
		t.Fatal("expected nil key pair")
	}
	checkErr(err)

	sig, err := SignMessage(0, []byte("m"), []byte("sk"))
	if sig != nil {
		t.Fatal("expected nil signature")
	}
	checkErr(err)

	ok, err := VerifyMessage(0, []byte("sig"), []byte("m"), []byte("pk"))
	if ok {
		t.Fatal("expected false verification result")
	}
	checkErr(err)
}
