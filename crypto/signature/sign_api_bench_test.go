package signature

import (
	"testing"
)

func BenchmarkKeygenAPI(b *testing.B) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	for _, scheme := range schemes {
		b.Run(scheme, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = KeygenAPI(scheme)
			}
		})
	}
}

func BenchmarkSignAPI(b *testing.B) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	message := []byte("test message")
	for _, scheme := range schemes {
		b.Run(scheme, func(b *testing.B) {
			sk, _ := KeygenAPI(scheme)
			for i := 0; i < b.N; i++ {
				_ = SignAPI(scheme, sk, message)
			}
		})
	}
}

func BenchmarkVerifyAPI(b *testing.B) {
	schemes := []string{"bls", "ecdsa", "ec_schnorr", "eddsa", "eddsa_cosmos", "sm2"}
	message := []byte("test message")
	for _, scheme := range schemes {
		b.Run(scheme, func(b *testing.B) {
			sk, pk := KeygenAPI(scheme)
			sig := SignAPI(scheme, sk, message)
			for i := 0; i < b.N; i++ {
				_ = VerifyAPI(scheme, pk, message, sig)
			}
		})
	}
}
