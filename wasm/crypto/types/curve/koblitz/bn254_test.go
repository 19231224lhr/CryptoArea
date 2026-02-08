package koblitz

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"blockchain-crypto/types/curve/bn254"
)

func TestIsOnCurve(t *testing.T) {
	p := g1.MulScalar(g1.New(), g1.One(), bn254.FrFromInt(123))
	fmt.Println(g1.IsOnCurve(p))
}

func TestEncodeToBN254G1(t *testing.T) {
	qBig, ok := new(big.Int).SetString("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 0)
	if !ok {
		t.Fatal("failed to parse field modulus")
	}
	twoExp := new(big.Int).Exp(big.NewInt(2), big.NewInt(5), nil)
	maxM := new(big.Int).Div(qBig, twoExp)
	for i := 0; i < 1024; i++ {
		var m *big.Int
		mPoint := EncodeToBN254G1(big.NewInt(0))
		mPoint = nil
		for attempt := 0; attempt < 32; attempt++ {
			m, _ = rand.Int(rand.Reader, maxM)
			mPoint = EncodeToBN254G1(m)
			if mPoint != nil {
				break
			}
		}
		if mPoint == nil {
			t.Fatal("failed to encode point after retries")
		}
		mRecover := DecodeFromBN254G1(mPoint)
		if m.Cmp(mRecover) != 0 {
			t.Fatalf("decoded value mismatch: got %s want %s", mRecover.String(), m.String())
		}
	}
}

func Test1(t *testing.T) {
	qBig, ok := new(big.Int).SetString("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", 0)
	if !ok {
		t.Fatal("failed to parse field modulus")
	}
	fmt.Println(qBig.BitLen())
	twoExp := new(big.Int).Exp(big.NewInt(2), big.NewInt(5), nil)
	maxNum := new(big.Int).Div(qBig, twoExp)
	fmt.Println(maxNum)
	fmt.Println(maxNum.BitLen())
}
