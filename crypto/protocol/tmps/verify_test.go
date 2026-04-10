package tmps

import (
	"math/big"
	"testing"

	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

func TestVerifyPairingChecks(t *testing.T) {
	input := buildVerificationFixture(t)

	results, err := VerifyPairingChecks(input, []PairingCheck{
		{
			Name: "pair_matches_gt",
			Terms: []PairingTerm{
				{G1: G1Ref{Bundle: BundlePK, Index: 0}, G2: G2Ref{Bundle: BundlePI, Index: 0}},
			},
			Expected: &GTRef{Bundle: BundlePI, Index: 0},
		},
		{
			Name: "pair_times_inverse_is_one",
			Terms: []PairingTerm{
				{G1: G1Ref{Bundle: BundlePK, Index: 0}, G2: G2Ref{Bundle: BundlePI, Index: 0}},
				{G1: G1Ref{Bundle: BundlePK, Index: 0}, G2: G2Ref{Bundle: BundlePI, Index: 0}, Invert: true},
			},
			ExpectOne: true,
		},
	})
	if err != nil {
		t.Fatalf("VerifyPairingChecks failed: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("unexpected result count: got %d want 2", len(results))
	}
	for _, result := range results {
		if !result.Valid {
			t.Fatalf("expected pairing check %s to be valid: %s", result.Name, result.Message)
		}
	}
}

func TestVerifyPairingChecksFailsMismatchedExpectation(t *testing.T) {
	input := buildVerificationFixture(t)
	results, err := VerifyPairingChecks(input, []PairingCheck{
		{
			Name: "pair_should_not_be_one",
			Terms: []PairingTerm{
				{G1: G1Ref{Bundle: BundlePK, Index: 0}, G2: G2Ref{Bundle: BundlePI, Index: 0}},
			},
			ExpectOne: true,
		},
	})
	if err != nil {
		t.Fatalf("VerifyPairingChecks failed: %v", err)
	}
	if len(results) != 1 || results[0].Valid {
		t.Fatal("expected mismatched pairing expectation to fail")
	}
}

func buildVerificationFixture(t *testing.T) *ProofInput {
	t.Helper()
	g1 := bn254.NewG1()
	g2 := bn254.NewG2()
	engine := bn254.NewEngine()

	p1 := g1.New()
	g1.MulScalarBig(p1, g1.One(), big.NewInt(5))
	p2 := g2.New()
	g2.MulScalarBig(p2, g2.One(), big.NewInt(7))
	gt := engine.AddPair(p1, p2).Result()

	return &ProofInput{
		Pk: &Bundle{
			G1:      []*bn254.PointG1{p1},
			Scalars: []*big.Int{big.NewInt(11)},
		},
		Challenge: big.NewInt(13),
		Pi: &Bundle{
			G2:      []*bn254.PointG2{p2},
			GT:      []*bn254.E{gt},
			Scalars: []*big.Int{big.NewInt(17)},
		},
		Vk: &Bundle{
			G1:      []*bn254.PointG1{g1.One()},
			G2:      []*bn254.PointG2{g2.One()},
			Scalars: []*big.Int{big.NewInt(19)},
		},
	}
}
