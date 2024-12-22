package koblitz

import (
	. "blockchain-crypto/types/curve/bn254"
	"math/big"
)

var (
	g1   = NewG1()
	K    = 32
	kBig = big.NewInt(int64(K))
	// (E/𝔽p): h²=X³+3
	// (Eₜ/𝔽p²): h² = X³+3/(u+9) (D-type twist)
	// p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
	// p = 3 mod 4
	p, _ = new(big.Int).SetString("21888242871839275222246405745257275088696311157297823662689037894645226208583", 10)
	// maxMessage :=
	// (p - 1) / 2
	eulerExp = new(big.Int)
	// (p + 1) / 4
	calcExp     = new(big.Int)
	eulerSymbol = big.NewInt(1)
)

func init() {
	// Euler exponent (p - 1) / 2
	eulerExp.Sub(p, big.NewInt(1)).Div(eulerExp, big.NewInt(2))
	// (p + 1) / 4
	calcExp.Add(p, big.NewInt(1)).Div(calcExp, big.NewInt(4))
}

func EncodeToBN254G1(m *big.Int) *PointG1 {
	if m.BitLen() > 248 {
		return nil
	}
	x := new(big.Int).Mul(m, kBig)
	for j := 0; j < K; j++ {
		//	x = mK+j
		x.Add(x, big.NewInt(1))
		// fmt.Println("x=", x)
		//	a = x^3 + 3 mod p
		a := new(big.Int)
		a.Exp(x, big.NewInt(3), p).Add(a, big.NewInt(3)).Mod(a, p)
		// fmt.Println("a=x^3+4 mod p=", a)
		// Euler criteria
		discriminator := new(big.Int).Exp(a, eulerExp, p)
		// fmt.Println("IsQuare Remain?", new(big.Int).Modulus(new(big.Int).Add(discriminator, big.FrFromInt(1)), p))
		if discriminator.Cmp(eulerSymbol) == 0 {
			// calc y (https://oi-wiki.org/math/number-theory/quad-residue/)
			// x^2 = a mod p (p is prime, p = 3 mod 4), one of the solutions is a^[(p+1)/4] mod p
			// y = a^[(p+1)/4] mod p
			y := new(big.Int).Exp(a, calcExp, p)
			xFe, _ := FromBig(x)
			yFe, _ := FromBig(y)
			candidate := &PointG1{*xFe, *yFe, *new(Fe).One()}
			if !g1.IsOnCurve(candidate) {
				continue
			}
			if !g1.InCorrectSubgroup(candidate) {
				continue
			}
			return candidate
		}
	}
	return nil
}

func DecodeFromBN254G1(point *PointG1) *big.Int {
	x := ToBig(&g1.Affine(point)[0])
	return new(big.Int).Div(x, kBig)
}
