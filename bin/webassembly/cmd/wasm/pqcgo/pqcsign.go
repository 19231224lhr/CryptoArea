package pqcgo

/*
#cgo CFLAGS: -I${SRCDIR}/libs/include
#cgo LDFLAGS: ${SRCDIR}/libs/lib/libpqmagic.a
#include <stdint.h>
#include <stdlib.h>
#include "./pqcsign_wrapper.h"
*/
import "C"
import (
	"encoding/hex"
	"errors"
	"unsafe"
)

func KeyGen(scheme int) (string, string, error) {
	pk := make([]byte, PUBLICKEYBYTES[scheme])
	sk := make([]byte, SECRETKEYBYTES[scheme])
	ret := C.keyGen(C.int(scheme), (*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if ret != 0 {
		return "", "", errors.New("key generation failed")
	}
	return hex.EncodeToString(pk), hex.EncodeToString(sk), nil
}

func KeyGenWithSeed(scheme int, seed []byte) (string, string, error) {
	pk := make([]byte, PUBLICKEYBYTES[scheme])
	sk := make([]byte, SECRETKEYBYTES[scheme])
	ret := C.keyGenWithSeed(C.int(scheme), (*C.uint8_t)(unsafe.Pointer(&pk[0])), (*C.uint8_t)(unsafe.Pointer(&sk[0])), (*C.uint8_t)(unsafe.Pointer(&seed[0])), C.size_t(len(seed)))
	if ret != 0 {
		return "", "", errors.New("key generation with seed failed")
	}
	return hex.EncodeToString(pk), hex.EncodeToString(sk), nil
}

func Sign(scheme int, message []byte, sk []byte) (string, error) {
	sig := make([]byte, SIGNATUREBYTES[scheme]+10)
	siglen := C.size_t(0)
	ret := C.sign(C.int(scheme), (*C.uint8_t)(unsafe.Pointer(&sig[0])), &siglen, (*C.uint8_t)(unsafe.Pointer(&message[0])), C.size_t(len(message)), (*C.uint8_t)(unsafe.Pointer(&sk[0])))
	if ret != 0 {
		return "", errors.New("signing failed")
	}
	return hex.EncodeToString(sig[:siglen]), nil
}

func Verify(scheme int, sig []byte, message []byte, pk []byte) (bool, error) {
	ret := C.verify(C.int(scheme), (*C.uint8_t)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)), (*C.uint8_t)(unsafe.Pointer(&message[0])), C.size_t(len(message)), (*C.uint8_t)(unsafe.Pointer(&pk[0])))
	if ret != 0 {
		return false, errors.New("verification failed")
	}
	return true, nil
}

func VerifyKeyGen(scheme int, fsk []byte, bsk []byte, bpk []byte) (bool, error) {
	ret := C.VerifyKeyGen(C.int(scheme), (*C.uint8_t)(unsafe.Pointer(&fsk[0])), (*C.uint8_t)(unsafe.Pointer(&bsk[0])), (*C.uint8_t)(unsafe.Pointer(&bpk[0])))
	if ret != 0 {
		return false, errors.New("key generation verification failed")
	}
	return true, nil
}
