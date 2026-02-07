//go:build cgo && windows

package pqcgo

import (
	"bytes"
	"testing"
)

func TestKEMParseSchemeName(t *testing.T) {
	tests := map[string]int{
		"ml_kem_512":  0,
		"ml_kem_768":  1,
		"ml_kem_1024": 2,
		"aigis_enc_1": 3,
		"aigis_enc_2": 4,
		"aigis_enc_3": 5,
		"aigis_enc_4": 6,
	}

	for name, want := range tests {
		got, err := ParseKEMSchemeName(name)
		if err != nil {
			t.Fatalf("ParseKEMSchemeName(%s) returned error: %v", name, err)
		}
		if got != want {
			t.Fatalf("ParseKEMSchemeName(%s) = %d, want %d", name, got, want)
		}
	}
}

func TestKEMRoundTrip(t *testing.T) {
	schemes := []int{1, 3}
	for _, scheme := range schemes {
		pk, sk, err := KEMKeyGen(scheme)
		if err != nil {
			t.Fatalf("KEMKeyGen failed for scheme %d: %v", scheme, err)
		}

		ct, ss1, err := KEMEncapsulate(scheme, pk)
		if err != nil {
			t.Fatalf("KEMEncapsulate failed for scheme %d: %v", scheme, err)
		}

		ss2, err := KEMDecapsulate(scheme, ct, sk)
		if err != nil {
			t.Fatalf("KEMDecapsulate failed for scheme %d: %v", scheme, err)
		}

		if !bytes.Equal(ss1, ss2) {
			t.Fatalf("shared secret mismatch for scheme %d", scheme)
		}
	}
}

func TestKEMInvalidInputs(t *testing.T) {
	if _, _, err := KEMKeyGen(-1); err == nil {
		t.Fatal("expected KEMKeyGen to fail on invalid scheme")
	}

	if _, _, err := KEMEncapsulate(1, nil); err == nil {
		t.Fatal("expected KEMEncapsulate to fail on empty public key")
	}

	pk, sk, err := KEMKeyGen(1)
	if err != nil {
		t.Fatalf("KEMKeyGen failed: %v", err)
	}
	_ = pk

	if _, err := KEMDecapsulate(1, []byte{1, 2, 3}, sk); err == nil {
		t.Fatal("expected KEMDecapsulate to fail on invalid ciphertext length")
	}
}
