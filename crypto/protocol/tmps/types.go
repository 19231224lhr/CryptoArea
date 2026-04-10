package tmps

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

// Bundle groups the curve elements and scalars that make up one TMPS payload
// section. The structure is intentionally generic so callers can preserve
// legacy layouts while a more protocol-specific API evolves.
type Bundle struct {
	G1      []*bn254.PointG1
	G2      []*bn254.PointG2
	GT      []*bn254.E
	Scalars []*big.Int
}

// ProofInput holds the four major values most external TMPS integrations need
// to exchange: public key material, challenge, proof payload, and verifier key.
type ProofInput struct {
	Pk        *Bundle
	Challenge *big.Int
	Pi        *Bundle
	Vk        *Bundle
}

// ChallengeMaterial is the deterministic input used to derive a protocol
// challenge when a caller wants the library to build it.
type ChallengeMaterial struct {
	Pk      *Bundle
	Vk      *Bundle
	Context []byte
	Nonce   []byte
}

// VerificationInput provides the proof envelope plus optional expected digests
// from an external system.
type VerificationInput struct {
	ProofInput            *ProofInput
	ExpectedProofHash     []byte
	ExpectedPublicKeyHash []byte
	ExpectedChallengeHash []byte
}

// VerificationResult reports what was checked by the current TMPS service
// implementation. This intentionally focuses on structural and byte-level
// integrity; it does not claim full protocol soundness on its own.
type VerificationResult struct {
	Valid              bool
	StructuralValid    bool
	HashesMatch        bool
	ProofHash          []byte
	PublicKeyHash      []byte
	ChallengeHash      []byte
	GeneratedChallenge *big.Int
	Checks             []CheckResult
	Messages           []string
}

type CheckResult struct {
	Name    string
	Valid   bool
	Message string
}

type BundleSelector string

const (
	BundlePK BundleSelector = "pk"
	BundlePI BundleSelector = "pi"
	BundleVK BundleSelector = "vk"
)

type G1Ref struct {
	Bundle BundleSelector
	Index  int
}

type G2Ref struct {
	Bundle BundleSelector
	Index  int
}

type GTRef struct {
	Bundle BundleSelector
	Index  int
}

type PairingTerm struct {
	G1     G1Ref
	G2     G2Ref
	Invert bool
}

type PairingCheck struct {
	Name      string
	Terms     []PairingTerm
	ExpectOne bool
	Expected  *GTRef
}

type VerifyOptions struct {
	ChallengeMaterial *ChallengeMaterial
	PairingChecks     []PairingCheck
}

// Service captures the stable byte-level operations a TMPS integration needs
// before higher-level prove/verify logic is finalized.
type Service interface {
	CodecName() string
	HashAlgorithm() string
	MarshalProofInput(input *ProofInput) ([]byte, error)
	UnmarshalProofInput(data []byte) (*ProofInput, error)
	MarshalChallengeMaterial(material *ChallengeMaterial) ([]byte, error)
	MarshalBundle(bundle *Bundle) ([]byte, error)
	UnmarshalBundle(data []byte) (*Bundle, error)
	MarshalChallenge(challenge *big.Int) ([]byte, error)
	UnmarshalChallenge(data []byte) (*big.Int, error)
	GenerateChallenge(material *ChallengeMaterial) (*big.Int, error)
	VerifyEnvelope(input *VerificationInput) (*VerificationResult, error)
	VerifyWithPlan(input *ProofInput, options *VerifyOptions) (*VerificationResult, error)
	ProofHash(input *ProofInput) ([]byte, error)
	PublicKeyHash(bundle *Bundle) ([]byte, error)
	ChallengeHash(challenge *big.Int) ([]byte, error)
}

func ValidateBundle(bundle *Bundle) error {
	if bundle == nil {
		return fmt.Errorf("bundle must not be nil")
	}
	var issues []error
	g1 := bn254.NewG1()
	g2 := bn254.NewG2()
	gt := bn254.NewGT()

	for i, point := range bundle.G1 {
		if point == nil {
			issues = append(issues, fmt.Errorf("g1[%d] must not be nil", i))
			continue
		}
		if !g1.IsOnCurve(point) {
			issues = append(issues, fmt.Errorf("g1[%d] is not on curve", i))
			continue
		}
		if !g1.InCorrectSubgroup(point) {
			issues = append(issues, fmt.Errorf("g1[%d] is not in the correct subgroup", i))
		}
	}
	for i, point := range bundle.G2 {
		if point == nil {
			issues = append(issues, fmt.Errorf("g2[%d] must not be nil", i))
			continue
		}
		if !g2.IsOnCurve(point) {
			issues = append(issues, fmt.Errorf("g2[%d] is not on curve", i))
			continue
		}
		if !g2.InCorrectSubgroup(point) {
			issues = append(issues, fmt.Errorf("g2[%d] is not in the correct subgroup", i))
		}
	}
	for i, element := range bundle.GT {
		if element == nil {
			issues = append(issues, fmt.Errorf("gt[%d] must not be nil", i))
			continue
		}
		encoded := gt.ToBytes(element)
		decoded, err := gt.FromBytes(encoded)
		if err != nil {
			issues = append(issues, fmt.Errorf("gt[%d] failed subgroup validation: %w", i, err))
			continue
		}
		if !decoded.Equal(element) {
			issues = append(issues, fmt.Errorf("gt[%d] changed during canonical round-trip", i))
		}
	}
	for i, scalar := range bundle.Scalars {
		if scalar == nil {
			issues = append(issues, fmt.Errorf("scalars[%d] must not be nil", i))
			continue
		}
		if scalar.Sign() < 0 {
			issues = append(issues, fmt.Errorf("scalars[%d] must not be negative", i))
			continue
		}
		if scalar.Cmp(bn254.Order) >= 0 {
			issues = append(issues, fmt.Errorf("scalars[%d] must be < curve order", i))
		}
	}
	return joinIssues(issues)
}

func ValidateChallenge(challenge *big.Int) error {
	if challenge == nil {
		return fmt.Errorf("challenge must not be nil")
	}
	if challenge.Sign() < 0 {
		return fmt.Errorf("challenge must not be negative")
	}
	if challenge.Cmp(bn254.Order) >= 0 {
		return fmt.Errorf("challenge must be < curve order")
	}
	return nil
}

func ValidateProofInput(input *ProofInput) error {
	if input == nil {
		return fmt.Errorf("proof input must not be nil")
	}
	var issues []error
	if input.Pk == nil {
		issues = append(issues, fmt.Errorf("pk must not be nil"))
	} else if err := ValidateBundle(input.Pk); err != nil {
		issues = append(issues, fmt.Errorf("pk: %w", err))
	}
	if input.Pi == nil {
		issues = append(issues, fmt.Errorf("pi must not be nil"))
	} else if err := ValidateBundle(input.Pi); err != nil {
		issues = append(issues, fmt.Errorf("pi: %w", err))
	}
	if input.Vk == nil {
		issues = append(issues, fmt.Errorf("vk must not be nil"))
	} else if err := ValidateBundle(input.Vk); err != nil {
		issues = append(issues, fmt.Errorf("vk: %w", err))
	}
	if err := ValidateChallenge(input.Challenge); err != nil {
		issues = append(issues, err)
	}
	return joinIssues(issues)
}

func ValidateChallengeMaterial(material *ChallengeMaterial) error {
	if material == nil {
		return fmt.Errorf("challenge material must not be nil")
	}
	var issues []error
	if material.Pk == nil {
		issues = append(issues, fmt.Errorf("pk must not be nil"))
	} else if err := ValidateBundle(material.Pk); err != nil {
		issues = append(issues, fmt.Errorf("pk: %w", err))
	}
	if material.Vk == nil {
		issues = append(issues, fmt.Errorf("vk must not be nil"))
	} else if err := ValidateBundle(material.Vk); err != nil {
		issues = append(issues, fmt.Errorf("vk: %w", err))
	}
	if len(material.Context) == 0 {
		issues = append(issues, fmt.Errorf("context must not be empty"))
	}
	if len(material.Nonce) == 0 {
		issues = append(issues, fmt.Errorf("nonce must not be empty"))
	}
	return joinIssues(issues)
}

func joinIssues(issues []error) error {
	if len(issues) == 0 {
		return nil
	}
	messages := make([]string, 0, len(issues))
	for _, issue := range issues {
		if issue == nil {
			continue
		}
		messages = append(messages, issue.Error())
	}
	if len(messages) == 0 {
		return nil
	}
	return errors.New(strings.Join(messages, "; "))
}
