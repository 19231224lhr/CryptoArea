//go:build cgo

package pqcgo

/*
#cgo CFLAGS: -I${SRCDIR}/libs/include
#cgo windows LDFLAGS: ${SRCDIR}/libs/lib/win/libpqmagic.a
#cgo linux LDFLAGS: ${SRCDIR}/libs/lib/linux/libpqmagic.a
#include <stdint.h>
#include <stdlib.h>
#include "./pqcsign_wrapper.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

func validateScheme(scheme int) error {
	if scheme < 0 || scheme >= len(PUBLICKEYBYTES) {
		return fmt.Errorf("invalid scheme: %d", scheme)
	}
	return nil
}

func validateExactLen(name string, got int, want int) error {
	if got != want {
		return fmt.Errorf("invalid %s length: got %d want %d", name, got, want)
	}
	return nil
}

func bytesPtr(data []byte) *C.uint8_t {
	if len(data) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&data[0]))
}

func KeyGen(scheme int) ([]byte, []byte, error) {
	if err := validateScheme(scheme); err != nil {
		return nil, nil, err
	}

	pk := make([]byte, PUBLICKEYBYTES[scheme])
	sk := make([]byte, SECRETKEYBYTES[scheme])
	ret := C.keyGen(C.int(scheme), bytesPtr(pk), bytesPtr(sk))
	if ret != 0 {
		return nil, nil, errors.New("key generation failed")
	}
	return pk, sk, nil
}

func KeyGenWithSeed(scheme int, seed []byte) ([]byte, []byte, error) {
	if err := validateScheme(scheme); err != nil {
		return nil, nil, err
	}
	if len(seed) == 0 {
		return nil, nil, errors.New("seed must not be empty")
	}

	pk := make([]byte, PUBLICKEYBYTES[scheme])
	sk := make([]byte, SECRETKEYBYTES[scheme])
	ret := C.keyGenWithSeed(C.int(scheme), bytesPtr(pk), bytesPtr(sk), bytesPtr(seed), C.size_t(len(seed)))
	if ret != 0 {
		return nil, nil, errors.New("key generation with seed failed")
	}
	return pk, sk, nil
}

func Sign(scheme int, message []byte, sk []byte) ([]byte, error) {
	if err := validateScheme(scheme); err != nil {
		return nil, err
	}
	if err := validateExactLen("secret key", len(sk), SECRETKEYBYTES[scheme]); err != nil {
		return nil, err
	}

	sig := make([]byte, SIGNATUREBYTES[scheme])
	siglen := C.size_t(0)
	ret := C.sign(C.int(scheme), bytesPtr(sig), &siglen, bytesPtr(message), C.size_t(len(message)), bytesPtr(sk))
	if ret != 0 {
		return nil, errors.New("signing failed")
	}
	if int(siglen) <= 0 || int(siglen) > len(sig) {
		return nil, errors.New("signing failed: invalid signature length")
	}
	return sig[:siglen], nil
}

func Verify(scheme int, sig []byte, message []byte, pk []byte) (bool, error) {
	if err := validateScheme(scheme); err != nil {
		return false, err
	}
	if err := validateExactLen("signature", len(sig), SIGNATUREBYTES[scheme]); err != nil {
		return false, err
	}
	if err := validateExactLen("public key", len(pk), PUBLICKEYBYTES[scheme]); err != nil {
		return false, err
	}

	ret := C.verify(C.int(scheme), bytesPtr(sig), C.size_t(len(sig)), bytesPtr(message), C.size_t(len(message)), bytesPtr(pk))
	if ret != 0 {
		return false, errors.New("verification failed")
	}
	return true, nil
}

func VerifyKeyGen(scheme int, fsk []byte, bsk []byte, bpk []byte) (bool, error) {
	if err := validateScheme(scheme); err != nil {
		return false, err
	}
	if err := validateExactLen("forward secret key", len(fsk), SECRETKEYBYTES[scheme]); err != nil {
		return false, err
	}
	if err := validateExactLen("backward secret key", len(bsk), SECRETKEYBYTES[scheme]); err != nil {
		return false, err
	}
	if err := validateExactLen("backward public key", len(bpk), PUBLICKEYBYTES[scheme]); err != nil {
		return false, err
	}

	ret := C.VerifyKeyGen(C.int(scheme), bytesPtr(fsk), bytesPtr(bsk), bytesPtr(bpk))
	if ret != 0 {
		return false, errors.New("key generation verification failed")
	}
	return true, nil
}
