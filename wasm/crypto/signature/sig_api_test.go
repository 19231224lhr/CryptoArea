package signature

import (
	"testing"
)

func Test_KeygenAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	for _, scheme := range schemes {
		sk, pk := KeygenAPI(scheme)
		if sk == nil || pk == nil {
			t.Errorf("KeygenAPI failed for scheme: %s", scheme)
		}
	}
}

func Test_KeygenWithSeedAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	seed := []byte("testseedtestseedtestseedtestseed")
	for _, scheme := range schemes {
		sk, pk := KeygenWithSeedAPI(scheme, seed)
		if sk == nil || pk == nil {
			t.Errorf("KeygenWithSeedAPI failed for scheme: %s", scheme)
		}
	}
}

func Test_KeygenExtendAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	tValue := uint8(3)
	for _, scheme := range schemes {
		sks, pks := KeygenExtendAPI(scheme, tValue)
		if len(sks) != int(tValue) || len(pks) != int(tValue) {
			t.Errorf("KeygenExtendAPI failed for scheme: %s", scheme)
		}
	}
}

func Test_SignAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	message := []byte("this is a test")
	for _, scheme := range schemes {
		sk, _ := KeygenAPI(scheme)
		sig := SignAPI(scheme, sk, message)
		if sig == nil {
			t.Errorf("SignAPI failed for scheme: %s", scheme)
		}
	}
}

func Test_VerifyAPI(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	message := []byte("this is a test")
	for _, scheme := range schemes {
		sk, pk := KeygenAPI(scheme)
		sig := SignAPI(scheme, sk, message)
		result := VerifyAPI(scheme, pk, message, sig)
		if !result {
			t.Errorf("VerifyAPI failed for scheme: %s", scheme)
		}
	}
}

func Test_VerifyKeyGen(t *testing.T) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	seed := []byte("testseedtestseedtestseedtestseed")
	for _, scheme := range schemes {
		forwardPK, _ := KeygenWithSeedAPI(scheme, seed)
		backwardSK, backwardPK := KeygenWithSeedAPI(scheme, forwardPK)
		result := VerifyKeyGen(scheme, forwardPK, backwardSK, backwardPK)
		if !result {
			t.Errorf("VerifyKeyGen failed for scheme: %s", scheme)
		}
	}
}
