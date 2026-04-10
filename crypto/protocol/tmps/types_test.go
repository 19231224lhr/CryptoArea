package tmps

import (
	"math/big"
	"testing"

	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

func TestValidateBundleAndProofInput(t *testing.T) {
	g1 := bn254.NewG1()
	g2 := bn254.NewG2()
	engine := bn254.NewEngine()

	p1 := g1.New()
	g1.MulScalarBig(p1, g1.One(), big.NewInt(5))
	p2 := g2.New()
	g2.MulScalarBig(p2, g2.One(), big.NewInt(7))
	gt := engine.AddPair(p1, p2).Result()

	validBundle := &Bundle{
		G1:      []*bn254.PointG1{p1},
		G2:      []*bn254.PointG2{p2},
		GT:      []*bn254.E{gt},
		Scalars: []*big.Int{big.NewInt(11)},
	}
	if err := ValidateBundle(validBundle); err != nil {
		t.Fatalf("ValidateBundle failed: %v", err)
	}

	validProofInput := &ProofInput{
		Pk:        &Bundle{G1: []*bn254.PointG1{p1}, Scalars: []*big.Int{big.NewInt(11)}},
		Challenge: big.NewInt(13),
		Pi:        &Bundle{G2: []*bn254.PointG2{p2}, GT: []*bn254.E{gt}, Scalars: []*big.Int{big.NewInt(17)}},
		Vk:        &Bundle{G1: []*bn254.PointG1{g1.One()}, G2: []*bn254.PointG2{g2.One()}, Scalars: []*big.Int{big.NewInt(19)}},
	}
	if err := ValidateProofInput(validProofInput); err != nil {
		t.Fatalf("ValidateProofInput failed: %v", err)
	}
}

func TestValidateChallengeMaterialRejectsMissingFields(t *testing.T) {
	if err := ValidateChallengeMaterial(nil); err == nil {
		t.Fatal("expected ValidateChallengeMaterial to fail")
	}
	material := &ChallengeMaterial{}
	if err := ValidateChallengeMaterial(material); err == nil {
		t.Fatal("expected ValidateChallengeMaterial to fail for missing fields")
	}
}

func TestValidateChallengeRejectsOutOfRangeValues(t *testing.T) {
	if err := ValidateChallenge(nil); err == nil {
		t.Fatal("expected nil challenge validation to fail")
	}
	if err := ValidateChallenge(new(big.Int).Set(bn254.Order)); err == nil {
		t.Fatal("expected out-of-range challenge validation to fail")
	}
}
