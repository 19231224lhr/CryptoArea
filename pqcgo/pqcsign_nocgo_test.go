//go:build !cgo

package pqcgo

import (
	"strings"
	"testing"
)

func TestNoCGOStubsReturnError(t *testing.T) {
	checkErr := func(err error) {
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "requires cgo") {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	_, _, err := KeyGen(0)
	checkErr(err)

	_, _, err = KeyGenWithSeed(0, []byte("seed"))
	checkErr(err)

	_, err = Sign(0, []byte("m"), []byte("sk"))
	checkErr(err)

	ok, err := Verify(0, []byte("sig"), []byte("m"), []byte("pk"))
	if ok {
		t.Fatal("expected false result")
	}
	checkErr(err)

	ok, err = VerifyKeyGen(0, []byte("fsk"), []byte("bsk"), []byte("bpk"))
	if ok {
		t.Fatal("expected false result")
	}
	checkErr(err)

	_, _, err = KEMKeyGen(1)
	checkErr(err)

	if _, err = ParseKEMSchemeName("ml_kem_768"); err != nil {
		t.Fatalf("ParseKEMSchemeName returned error: %v", err)
	}

	_, _, err = KEMEncapsulate(1, []byte("pk"))
	checkErr(err)

	_, err = KEMDecapsulate(1, []byte("ct"), []byte("sk"))
	checkErr(err)
}
