package pqcgo

import (
	"encoding/hex"
	"testing"
)

func TestKeyGen(t *testing.T) {
	for scheme := 0; scheme < 4; scheme++ {
		pk, sk, err := KeyGen(scheme)
		if err != nil {
			t.Fatalf("KeyGen failed for scheme %d: %v", scheme, err)
		}
		if len(pk) == 0 || len(sk) == 0 {
			t.Fatalf("KeyGen returned empty keys for scheme %d", scheme)
		}
		t.Logf("scheme:%d, pk: %s\n,sk: %s", scheme, pk, sk)
	}
}

func TestKeyGenWithSeed(t *testing.T) {
	seed := []byte("thisisaseed")
	for scheme := 0; scheme < 4; scheme++ {
		pk, sk, err := KeyGenWithSeed(scheme, seed)
		if err != nil {
			t.Fatalf("KeyGenWithSeed failed for scheme %d: %v", scheme, err)
		}
		if len(pk) == 0 || len(sk) == 0 {
			t.Fatalf("KeyGenWithSeed returned empty keys for scheme %d", scheme)
		}
		t.Logf("scheme:%d, pk: %s\n,sk: %s", scheme, pk, sk)
	}
}

func TestSign(t *testing.T) {
	message := []byte("test message")
	for scheme := 0; scheme < 4; scheme++ {
		_, sk, err := KeyGen(scheme)
		if err != nil {
			t.Fatalf("KeyGen failed for scheme %d: %v", scheme, err)
		}
		skBytes, _ := hex.DecodeString(sk)
		sig, err := Sign(scheme, message, skBytes)
		if err != nil {
			t.Fatalf("Sign failed for scheme %d: %v", scheme, err)
		}
		if len(sig) == 0 {
			t.Fatalf("Sign returned empty signature for scheme %d", scheme)
		}
		t.Logf("scheme:%d, sk: %s\n,sig: %s", scheme, sk, sig)
	}
}

func TestVerify(t *testing.T) {
	message := []byte("test message")
	for scheme := 0; scheme < 4; scheme++ {
		pk, sk, err := KeyGen(scheme)
		if err != nil {
			t.Fatalf("KeyGen failed for scheme %d: %v", scheme, err)
		}
		skBytes, _ := hex.DecodeString(sk)
		sig, err := Sign(scheme, message, skBytes)
		if err != nil {
			t.Fatalf("Sign failed for scheme %d: %v", scheme, err)
		}
		sigBytes, _ := hex.DecodeString(sig)
		pkBytes, _ := hex.DecodeString(pk)
		valid, err := Verify(scheme, sigBytes, message, pkBytes)
		if err != nil {
			t.Fatalf("Verify failed for scheme %d: %v", scheme, err)
		}
		if !valid {
			t.Fatalf("Verify returned false for scheme %d", scheme)
		}
	}
}

func TestVerifyKeyGen(t *testing.T) {
	for scheme := 0; scheme < 4; scheme++ {
		_, fsk, err := KeyGen(scheme)
		if err != nil {
			t.Fatalf("KeyGen failed for scheme %d: %v", scheme, err)
		}
		fskBytes, _ := hex.DecodeString(fsk)
		bpk, bsk, err := KeyGenWithSeed(scheme, fskBytes)
		if err != nil {
			t.Fatalf("KeyGen failed for scheme %d: %v", scheme, err)
		}
		bskBytes, _ := hex.DecodeString(bsk)
		bpkBytes, _ := hex.DecodeString(bpk)
		valid, err := VerifyKeyGen(scheme, fskBytes, bskBytes, bpkBytes)
		if err != nil {
			t.Fatalf("VerifyKeyGen failed for scheme %d: %v", scheme, err)
		}
		if !valid {
			t.Fatalf("VerifyKeyGen returned false for scheme %d", scheme)
		}
	}
}
