//go:build !cgo

package pqcgo

import (
	"errors"
	"fmt"
	"strings"
)

var errRequiresCGO = errors.New("pqcgo requires cgo")

func KeyGen(scheme int) ([]byte, []byte, error) {
	return nil, nil, errRequiresCGO
}

func KeyGenWithSeed(scheme int, seed []byte) ([]byte, []byte, error) {
	return nil, nil, errRequiresCGO
}

func Sign(scheme int, message []byte, sk []byte) ([]byte, error) {
	return nil, errRequiresCGO
}

func Verify(scheme int, sig []byte, message []byte, pk []byte) (bool, error) {
	return false, errRequiresCGO
}

func VerifyKeyGen(scheme int, fsk []byte, bsk []byte, bpk []byte) (bool, error) {
	return false, errRequiresCGO
}

func ParseKEMSchemeName(name string) (int, error) {
	scheme, ok := PQCKEMType[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return -1, fmt.Errorf("unsupported kem scheme name: %s", name)
	}
	return scheme, nil
}

func KEMKeyGen(scheme int) ([]byte, []byte, error) {
	return nil, nil, errRequiresCGO
}

func KEMEncapsulate(scheme int, pk []byte) ([]byte, []byte, error) {
	return nil, nil, errRequiresCGO
}

func KEMDecapsulate(scheme int, ct []byte, sk []byte) ([]byte, error) {
	return nil, errRequiresCGO
}
