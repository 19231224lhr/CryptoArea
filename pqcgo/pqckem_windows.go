//go:build cgo && windows

package pqcgo

/*
#cgo CFLAGS: -I${SRCDIR}/libs/include
#cgo windows LDFLAGS: ${SRCDIR}/libs/lib/win/libpqmagic_ml_kem_std.a
#cgo windows LDFLAGS: ${SRCDIR}/libs/lib/win/libpqmagic_aigis_enc_std.a
#cgo windows LDFLAGS: ${SRCDIR}/libs/lib/win/libpqmagic.a
#include <stdint.h>
#include "./pqckem_wrapper.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
)

func validateKEMScheme(scheme int) error {
	if scheme < 0 || scheme >= len(KEM_PUBLICKEYBYTES) {
		return fmt.Errorf("invalid kem scheme: %d", scheme)
	}
	return nil
}

func ParseKEMSchemeName(name string) (int, error) {
	scheme, ok := PQCKEMType[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return -1, fmt.Errorf("unsupported kem scheme name: %s", name)
	}
	return scheme, nil
}

func KEMKeyGen(scheme int) ([]byte, []byte, error) {
	if err := validateKEMScheme(scheme); err != nil {
		return nil, nil, err
	}

	pk := make([]byte, KEM_PUBLICKEYBYTES[scheme])
	sk := make([]byte, KEM_SECRETKEYBYTES[scheme])
	ret := C.kemKeyGen(C.int(scheme), bytesPtr(pk), bytesPtr(sk))
	if ret != 0 {
		return nil, nil, errors.New("kem key generation failed")
	}
	return pk, sk, nil
}

func KEMEncapsulate(scheme int, pk []byte) ([]byte, []byte, error) {
	if err := validateKEMScheme(scheme); err != nil {
		return nil, nil, err
	}
	if err := validateExactLen("kem public key", len(pk), KEM_PUBLICKEYBYTES[scheme]); err != nil {
		return nil, nil, err
	}

	ct := make([]byte, KEM_CIPHERTEXTBYTES[scheme])
	ss := make([]byte, KEM_SSBYTES[scheme])
	ret := C.kemEncaps(C.int(scheme), bytesPtr(ct), bytesPtr(ss), bytesPtr(pk))
	if ret != 0 {
		return nil, nil, errors.New("kem encapsulation failed")
	}
	return ct, ss, nil
}

func KEMDecapsulate(scheme int, ct []byte, sk []byte) ([]byte, error) {
	if err := validateKEMScheme(scheme); err != nil {
		return nil, err
	}
	if err := validateExactLen("kem ciphertext", len(ct), KEM_CIPHERTEXTBYTES[scheme]); err != nil {
		return nil, err
	}
	if err := validateExactLen("kem secret key", len(sk), KEM_SECRETKEYBYTES[scheme]); err != nil {
		return nil, err
	}

	ss := make([]byte, KEM_SSBYTES[scheme])
	ret := C.kemDecaps(C.int(scheme), bytesPtr(ss), bytesPtr(ct), bytesPtr(sk))
	if ret != 0 {
		return nil, errors.New("kem decapsulation failed")
	}
	return ss, nil
}
