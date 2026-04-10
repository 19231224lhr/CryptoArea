package tmps

import (
	"fmt"

	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

func VerifyPairingChecks(input *ProofInput, checks []PairingCheck) ([]CheckResult, error) {
	if input == nil {
		return nil, fmt.Errorf("proof input must not be nil")
	}
	if len(checks) == 0 {
		return nil, nil
	}

	results := make([]CheckResult, 0, len(checks))
	engine := bn254.NewEngine()
	for i, check := range checks {
		name := check.Name
		if name == "" {
			name = fmt.Sprintf("pairing_check_%d", i)
		}
		if len(check.Terms) == 0 {
			return nil, fmt.Errorf("%s: pairing check must contain at least one term", name)
		}

		for _, term := range check.Terms {
			g1Point, err := resolveG1Ref(input, term.G1)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			g2Point, err := resolveG2Ref(input, term.G2)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if term.Invert {
				engine.AddPairInv(g1Point, g2Point)
			} else {
				engine.AddPair(g1Point, g2Point)
			}
		}

		value := engine.Result()
		checkResult := CheckResult{Name: name, Valid: true}
		if check.ExpectOne {
			checkResult.Valid = value.IsOne()
			if checkResult.Valid {
				checkResult.Message = "pairing result equals one"
			} else {
				checkResult.Message = "pairing result does not equal one"
			}
		} else {
			if check.Expected == nil {
				return nil, fmt.Errorf("%s: expected target is required when ExpectOne is false", name)
			}
			expected, err := resolveGTRef(input, *check.Expected)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			checkResult.Valid = value.Equal(expected)
			if checkResult.Valid {
				checkResult.Message = "pairing result matches expected target"
			} else {
				checkResult.Message = "pairing result does not match expected target"
			}
		}
		results = append(results, checkResult)
	}
	return results, nil
}

func resolveBundle(input *ProofInput, selector BundleSelector) (*Bundle, error) {
	switch selector {
	case BundlePK:
		if input.Pk == nil {
			return nil, fmt.Errorf("pk bundle is nil")
		}
		return input.Pk, nil
	case BundlePI:
		if input.Pi == nil {
			return nil, fmt.Errorf("pi bundle is nil")
		}
		return input.Pi, nil
	case BundleVK:
		if input.Vk == nil {
			return nil, fmt.Errorf("vk bundle is nil")
		}
		return input.Vk, nil
	default:
		return nil, fmt.Errorf("unsupported bundle selector: %s", selector)
	}
}

func resolveG1Ref(input *ProofInput, ref G1Ref) (*bn254.PointG1, error) {
	bundle, err := resolveBundle(input, ref.Bundle)
	if err != nil {
		return nil, err
	}
	if ref.Index < 0 || ref.Index >= len(bundle.G1) {
		return nil, fmt.Errorf("%s.g1 index out of range: %d", ref.Bundle, ref.Index)
	}
	return bundle.G1[ref.Index], nil
}

func resolveG2Ref(input *ProofInput, ref G2Ref) (*bn254.PointG2, error) {
	bundle, err := resolveBundle(input, ref.Bundle)
	if err != nil {
		return nil, err
	}
	if ref.Index < 0 || ref.Index >= len(bundle.G2) {
		return nil, fmt.Errorf("%s.g2 index out of range: %d", ref.Bundle, ref.Index)
	}
	return bundle.G2[ref.Index], nil
}

func resolveGTRef(input *ProofInput, ref GTRef) (*bn254.E, error) {
	bundle, err := resolveBundle(input, ref.Bundle)
	if err != nil {
		return nil, err
	}
	if ref.Index < 0 || ref.Index >= len(bundle.GT) {
		return nil, fmt.Errorf("%s.gt index out of range: %d", ref.Bundle, ref.Index)
	}
	return bundle.GT[ref.Index], nil
}
