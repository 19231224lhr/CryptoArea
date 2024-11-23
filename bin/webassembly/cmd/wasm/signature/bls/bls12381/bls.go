package bls12381

import (
	. "blockchain-crypto/types/curve/bls12381"
	"crypto/rand"
)

var (
	AugSchemeDst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_")
)

func Keygen() (*Fr, *PointG1) {
	group1 := NewG1()
	sk, _ := NewFr().Rand(rand.Reader)
	pk := group1.MulScalar(group1.New(), group1.One(), sk)
	return sk, pk
}
func KeygenAPI() ([]byte, []byte) {
	group1 := NewG1()
	sk, _ := NewFr().Rand(rand.Reader)
	pk := group1.MulScalar(group1.New(), group1.One(), sk)
	return sk.ToBytes(), group1.ToBytes(pk)
}

func KeygenWithSeed(seed []byte) (*Fr, *PointG1) {
	group1 := NewG1()
	sk := HashToFr(seed)
	pk := group1.MulScalar(group1.New(), group1.One(), sk)
	return sk, pk
}

func KeygenWithSeedAPI(seed []byte) ([]byte, []byte) {
	group1 := NewG1()
	sk := HashToFr(seed)
	pk := group1.MulScalar(group1.New(), group1.One(), sk)
	return sk.ToBytes(), group1.ToBytes(pk)
}

func Sign(sk *Fr, message []byte) (signature *PointG2) {
	group2 := NewG2()
	h, _ := group2.HashToCurve(message, AugSchemeDst)
	// h^x
	signature = group2.MulScalar(group2.New(), h, sk)
	return signature
}
func SignAPI(sk []byte, message []byte) []byte {
	group2 := NewG2()
	h, _ := group2.HashToCurve(message, AugSchemeDst)
	// h^x
	return group2.ToBytes(group2.MulScalar(group2.New(), h, NewFr().FromBytes(sk)))
}

func Verify(pk *PointG1, message []byte, signature *PointG2) bool {
	group1 := NewG1()
	group2 := NewG2()
	h, _ := group2.HashToCurve(message, AugSchemeDst)
	// e(g_1,σ) ?= e(y,h)
	return NewPairingEngine().AddPair(pk, h).AddPairInv(group1.One(), signature).Check()
}

func VerifyAPI(pk []byte, message []byte, signature []byte) bool {
	group1 := NewG1()
	group2 := NewG2()
	pkPoint, err := group1.FromBytes(pk)
	if err != nil {
		return false
	}
	signaturePoint, err := group2.FromBytes(signature)
	if err != nil {
		return false
	}
	h, _ := group2.HashToCurve(message, AugSchemeDst)
	// e(g_1,σ) ?= e(y,h)
	return NewPairingEngine().AddPair(pkPoint, h).AddPairInv(group1.One(), signaturePoint).Check()
}
