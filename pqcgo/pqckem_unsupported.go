//go:build cgo && !windows

package pqcgo

import (
	"errors"
	"fmt"
	"strings"
)

var errKEMUnsupportedPlatform = errors.New("pqcgo kem is currently supported on windows cgo builds")

func ParseKEMSchemeName(name string) (int, error) {
	scheme, ok := PQCKEMType[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return -1, fmt.Errorf("unsupported kem scheme name: %s", name)
	}
	return scheme, nil
}

func KEMKeyGen(scheme int) ([]byte, []byte, error) {
	return nil, nil, errKEMUnsupportedPlatform
}

func KEMEncapsulate(scheme int, pk []byte) ([]byte, []byte, error) {
	return nil, nil, errKEMUnsupportedPlatform
}

func KEMDecapsulate(scheme int, ct []byte, sk []byte) ([]byte, error) {
	return nil, errKEMUnsupportedPlatform
}
