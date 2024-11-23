package signature_test

import (
	"blockchain-crypto/signature"
	"testing"
)

func TestKeygenAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	for _, scheme := range schemes {
		sk, pk := signature.KeygenAPI(scheme)
		if sk == nil || pk == nil {
			t.Errorf("KeygenAPI failed for scheme: %s", scheme)
		}
	}
}

func TestKeygenWithSeedAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	seed := []byte("testseedtestseedtestseedtestseed")
	for _, scheme := range schemes {
		sk, pk := signature.KeygenWithSeedAPI(scheme, seed)
		if sk == nil || pk == nil {
			t.Errorf("KeygenWithSeedAPI failed for scheme: %s", scheme)
		}
	}
}

func TestKeygenExtendAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	tValue := uint8(3)
	for _, scheme := range schemes {
		sk, pk := signature.KeygenExtendAPI(scheme, tValue)
		if sk == nil || pk == nil || len(sk) != int(tValue) || len(pk) != int(tValue) {
			t.Errorf("KeygenExtendAPI failed for scheme: %s", scheme)
		}
	}
}

func TestSignAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	mes := []byte("testmessage")
	for _, scheme := range schemes {
		sk, pk := signature.KeygenAPI(scheme)
		sig := signature.SignAPI(scheme, sk, mes)
		if sig == nil {
			t.Errorf("SignAPI failed for scheme: %s", scheme)
		}
		// Verify the signature
		result := signature.VerifyApi(scheme, pk, mes, sig)
		if !result {
			t.Errorf("VerifyApi failed for scheme: %s", scheme)
		}
	}
}

func TestVerifyApi(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	mes := []byte("testmessage")
	for _, scheme := range schemes {
		sk, pk := signature.KeygenAPI(scheme)
		sig := signature.SignAPI(scheme, sk, mes)
		result := signature.VerifyApi(scheme, pk, mes, sig)
		if !result {
			t.Errorf("VerifyApi failed for scheme: %s", scheme)
		}
	}
}

func TestVerifyKeyGen(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	forwardPK := []byte("testforwardpk")
	backwardSK := []byte("testbackwardsk")
	backwardPK := []byte("testbackwardpk")
	for _, scheme := range schemes {
		result := signature.VerifyKeyGen(scheme, forwardPK, backwardSK, backwardPK)
		if !result {
			t.Errorf("VerifyKeyGen failed for scheme: %s", scheme)
		}
	}
}
