//go:build cgo

package pqcgo

import (
	"bytes"
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
		//t.Logf("scheme:%d, pk: %s\n,sk: %s", scheme, hex.EncodeToString(pk), hex.EncodeToString(sk))
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
		//t.Logf("scheme:%d, pk: %s\n,sk: %s", scheme, hex.EncodeToString(pk), hex.EncodeToString(sk))
	}
}

func TestSign(t *testing.T) {
	message := []byte("test message")
	for scheme := 0; scheme < 4; scheme++ {
		_, sk, err := KeyGen(scheme)
		if err != nil {
			t.Fatalf("KeyGen failed for scheme %d: %v", scheme, err)
		}
		sig, err := Sign(scheme, message, sk)
		if err != nil {
			t.Fatalf("Sign failed for scheme %d: %v", scheme, err)
		}
		if len(sig) == 0 {
			t.Fatalf("Sign returned empty signature for scheme %d", scheme)
		}
		//t.Logf("scheme:%d, sk: %s\n,sig: %s", scheme, hex.EncodeToString(sk), hex.EncodeToString(sig))
	}
}

func TestVerify(t *testing.T) {
	message := []byte("test message")
	for scheme := 0; scheme < 4; scheme++ {
		pk, sk, err := KeyGen(scheme)
		if err != nil {
			t.Fatalf("KeyGen failed for scheme %d: %v", scheme, err)
		}
		sig, err := Sign(scheme, message, sk)
		if err != nil {
			t.Fatalf("Sign failed for scheme %d: %v", scheme, err)
		}
		valid, err := Verify(scheme, sig, message, pk)
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
		bpk, bsk, err := KeyGenWithSeed(scheme, fsk)
		if err != nil {
			t.Fatalf("KeyGenWithSeed failed for scheme %d: %v", scheme, err)
		}
		valid, err := VerifyKeyGen(scheme, fsk, bsk, bpk)
		if err != nil {
			t.Fatalf("VerifyKeyGen failed for scheme %d: %v", scheme, err)
		}
		if !valid {
			t.Fatalf("VerifyKeyGen returned false for scheme %d", scheme)
		}
	}
}

func TestKeyGenWithSeedDeterministicScheme3(t *testing.T) {
	seed := []byte("deterministic-seed-for-scheme-3")

	pk1, sk1, err := KeyGenWithSeed(3, seed)
	if err != nil {
		t.Fatalf("first KeyGenWithSeed failed: %v", err)
	}

	pk2, sk2, err := KeyGenWithSeed(3, seed)
	if err != nil {
		t.Fatalf("second KeyGenWithSeed failed: %v", err)
	}

	if !bytes.Equal(pk1, pk2) || !bytes.Equal(sk1, sk2) {
		t.Fatalf("scheme 3 key generation is not deterministic with the same seed")
	}
}

func TestMLDSAShortMessage(t *testing.T) {
	const scheme = 2
	message := []byte{0x42}

	pk, sk, err := KeyGen(scheme)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	sig, err := Sign(scheme, message, sk)
	if err != nil {
		t.Fatalf("Sign failed on short message: %v", err)
	}

	valid, err := Verify(scheme, sig, message, pk)
	if err != nil {
		t.Fatalf("Verify failed on short message: %v", err)
	}
	if !valid {
		t.Fatal("Verify returned false on short message")
	}
}

func TestInvalidInputsReturnError(t *testing.T) {
	t.Run("KeyGenInvalidScheme", func(t *testing.T) {
		if _, _, err := KeyGen(-1); err == nil {
			t.Fatal("expected error for invalid scheme")
		}
	})

	t.Run("KeyGenWithSeedEmptySeed", func(t *testing.T) {
		if _, _, err := KeyGenWithSeed(0, nil); err == nil {
			t.Fatal("expected error for empty seed")
		}
	})

	t.Run("SignInvalidSecretKeyLength", func(t *testing.T) {
		if _, err := Sign(0, []byte("m"), []byte{1}); err == nil {
			t.Fatal("expected error for invalid secret key length")
		}
	})

	t.Run("VerifyInvalidSignatureLength", func(t *testing.T) {
		if _, err := Verify(0, []byte{1}, []byte("m"), make([]byte, PUBLICKEYBYTES[0])); err == nil {
			t.Fatal("expected error for invalid signature length")
		}
	})

	t.Run("VerifyInvalidPublicKeyLength", func(t *testing.T) {
		if _, err := Verify(0, make([]byte, SIGNATUREBYTES[0]), []byte("m"), []byte{1}); err == nil {
			t.Fatal("expected error for invalid public key length")
		}
	})

	t.Run("VerifyKeyGenInvalidLengths", func(t *testing.T) {
		if _, err := VerifyKeyGen(0, []byte{1}, []byte{1}, []byte{1}); err == nil {
			t.Fatal("expected error for invalid key lengths")
		}
	})
}
