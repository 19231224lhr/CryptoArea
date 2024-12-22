package bls12381

import (
	"fmt"
	"testing"
)

func TestBLS(t *testing.T) {
	mes := []byte("this is a test")
	sk, pk := Keygen()
	sig := Sign(sk, mes)
	result := Verify(pk, mes, sig)
	fmt.Println(result)
}
