package signature

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func Test_ECDSA(t *testing.T) {
	scheme := "ecdsa"
	mes := []byte("this is a test")
	h := sha256.New()
	h.Write(mes)
	meshashed := h.Sum(nil)
	seck, pubk := KeygenAPI(scheme)
	sig := SignAPI(scheme, seck, meshashed)
	result := VerifyAPI(scheme, pubk, meshashed, sig)
	fmt.Println(result)
	// Output: true
}

func Test_ECSchnorr(t *testing.T) {
	scheme := "ec_schnorr"
	mes := []byte("this is a test")
	seck, pubk := KeygenAPI(scheme)
	sig := SignAPI(scheme, seck, mes)
	result := VerifyAPI(scheme, pubk, mes, sig)
	fmt.Println(result)
	// Output: true
}

func Test_BLS(t *testing.T) {
	scheme := "bls"
	mes := []byte("this is a test")
	seck, pubk := KeygenAPI(scheme)
	sig := SignAPI(scheme, seck, mes)
	result := VerifyAPI(scheme, pubk, mes, sig)
	fmt.Println(result)
	// Output: true
}

func Test_EdDSA(t *testing.T) {
	scheme := "eddsa"
	mes := []byte("this is a test")
	seck, pubk := KeygenAPI(scheme)
	sig := SignAPI(scheme, seck, mes)
	result := VerifyAPI(scheme, pubk, mes, sig)
	fmt.Println(result)
	// Output: true
}

func Test_EdDSACosmos(t *testing.T) {
	scheme := "eddsa_cosmos"
	mes := []byte("this is a test")
	seck, pubk := KeygenAPI(scheme)
	sig := SignAPI(scheme, seck, mes)
	result := VerifyAPI(scheme, pubk, mes, sig)
	fmt.Println(result)
	// Output: true
}

func Test_SM2(t *testing.T) {
	scheme := "sm2"
	mes := []byte("this is a test")
	seck, pubk := KeygenAPI(scheme)
	sig := SignAPI(scheme, seck, mes)
	result := VerifyAPI(scheme, pubk, mes, sig)
	fmt.Println(result)
	// Output: true
}
