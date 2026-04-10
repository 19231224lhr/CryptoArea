package tmps_test

import (
	"fmt"
	"math/big"

	"github.com/19231224lhr/CryptoArea/crypto/protocol/tmps"
	legacyv1 "github.com/19231224lhr/CryptoArea/crypto/protocol/tmps/codec/legacyv1"
	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

func Example() {
	g1 := bn254.NewG1()
	g2 := bn254.NewG2()
	engine := bn254.NewEngine()

	p1 := g1.New()
	g1.MulScalarBig(p1, g1.One(), big.NewInt(5))
	p2 := g2.New()
	g2.MulScalarBig(p2, g2.One(), big.NewInt(7))
	gt := engine.AddPair(p1, p2).Result()

	input := &tmps.ProofInput{
		Pk:        &tmps.Bundle{G1: []*bn254.PointG1{p1}, Scalars: []*big.Int{big.NewInt(11)}},
		Challenge: big.NewInt(13),
		Pi:        &tmps.Bundle{G2: []*bn254.PointG2{p2}, GT: []*bn254.E{gt}, Scalars: []*big.Int{big.NewInt(17)}},
		Vk:        &tmps.Bundle{G1: []*bn254.PointG1{g1.One()}, G2: []*bn254.PointG2{g2.One()}, Scalars: []*big.Int{big.NewInt(19)}},
	}

	service := legacyv1.MustNewService()
	result, err := service.VerifyWithPlan(input, &tmps.VerifyOptions{
		PairingChecks: []tmps.PairingCheck{
			{
				Name: "pair_matches_gt",
				Terms: []tmps.PairingTerm{
					{G1: tmps.G1Ref{Bundle: tmps.BundlePK, Index: 0}, G2: tmps.G2Ref{Bundle: tmps.BundlePI, Index: 0}},
				},
				Expected: &tmps.GTRef{Bundle: tmps.BundlePI, Index: 0},
			},
		},
	})
	fmt.Println(err == nil)
	fmt.Println(result.Valid)
	fmt.Println(len(result.Checks))
	// Output:
	// true
	// true
	// 1
}
