package koblitz

import (
	. "blockchain-crypto/curve/bn254"
	. "blockchain-crypto/utils"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestIsOnCurve(t *testing.T) {
	p := g1.MulScalar(g1.New(), g1.One(), FrFromInt(123))
	fmt.Println(g1.IsOnCurve(p))
}

func TestEncodeToBN254G1(t *testing.T) {
	qBig := BigFromHex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
	twoExp := new(big.Int).Exp(big.NewInt(2), big.NewInt(5), nil)
	maxM := new(big.Int).Div(qBig, twoExp)
	for i := 0; i < 1024; i++ {
		m, _ := rand.Int(rand.Reader, maxM)
		mPoint := EncodeToBN254G1(m)
		mRecover := DecodeFromBN254G1(mPoint)
		assert.True(t, m.Cmp(mRecover) == 0)
	}
}

func Test1(t *testing.T) {
	qBig := BigFromHex("0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001")
	fmt.Println(qBig.BitLen())
	twoExp := new(big.Int).Exp(big.NewInt(2), big.NewInt(5), nil)
	maxNum := new(big.Int).Div(qBig, twoExp)
	fmt.Println(maxNum)
	fmt.Println(maxNum.BitLen())
}
