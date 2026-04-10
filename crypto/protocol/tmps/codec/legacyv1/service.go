package legacyv1

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/19231224lhr/CryptoArea/crypto/protocol/tmps"
	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

type Option func(*Service)

type Service struct {
	hashAlgorithm string
}

func NewService(options ...Option) (*Service, error) {
	service := &Service{
		hashAlgorithm: tmps.HashAlgorithmKeccak256,
	}
	for _, option := range options {
		option(service)
	}
	if _, err := tmps.HashBytes(service.hashAlgorithm, nil); err != nil {
		return nil, err
	}
	return service, nil
}

func WithHashAlgorithm(algorithm string) Option {
	return func(service *Service) {
		service.hashAlgorithm = algorithm
	}
}

func MustNewService(options ...Option) *Service {
	service, err := NewService(options...)
	if err != nil {
		panic(err)
	}
	return service
}

func (s *Service) CodecName() string {
	return "tmps/legacyv1"
}

func (s *Service) HashAlgorithm() string {
	return s.hashAlgorithm
}

func (s *Service) MarshalProofInput(input *tmps.ProofInput) ([]byte, error) {
	return MarshalProofInput(input)
}

func (s *Service) UnmarshalProofInput(data []byte) (*tmps.ProofInput, error) {
	return UnmarshalProofInput(data)
}

func (s *Service) MarshalChallengeMaterial(material *tmps.ChallengeMaterial) ([]byte, error) {
	return MarshalChallengeMaterial(material)
}

func (s *Service) MarshalBundle(bundle *tmps.Bundle) ([]byte, error) {
	return MarshalBundle(bundle)
}

func (s *Service) UnmarshalBundle(data []byte) (*tmps.Bundle, error) {
	return UnmarshalBundle(data)
}

func (s *Service) MarshalChallenge(challenge *big.Int) ([]byte, error) {
	return MarshalChallenge(challenge)
}

func (s *Service) UnmarshalChallenge(data []byte) (*big.Int, error) {
	return UnmarshalChallenge(data)
}

func (s *Service) GenerateChallenge(material *tmps.ChallengeMaterial) (*big.Int, error) {
	if err := tmps.ValidateChallengeMaterial(material); err != nil {
		return nil, err
	}
	payload, err := s.MarshalChallengeMaterial(material)
	if err != nil {
		return nil, err
	}
	digest, err := tmps.HashBytes(s.hashAlgorithm, payload)
	if err != nil {
		return nil, err
	}
	challenge := new(big.Int).SetBytes(digest)
	challenge.Mod(challenge, bn254.Order)
	return challenge, nil
}

func (s *Service) VerifyEnvelope(input *tmps.VerificationInput) (*tmps.VerificationResult, error) {
	if input == nil {
		return nil, fmt.Errorf("verification input must not be nil")
	}
	result := &tmps.VerificationResult{
		StructuralValid: true,
		HashesMatch:     true,
	}
	if err := tmps.ValidateProofInput(input.ProofInput); err != nil {
		result.StructuralValid = false
		result.Messages = append(result.Messages, err.Error())
	}

	if input.ProofInput != nil {
		proofHash, err := s.ProofHash(input.ProofInput)
		if err != nil {
			return nil, err
		}
		publicKeyHash, err := s.PublicKeyHash(input.ProofInput.Pk)
		if err != nil {
			return nil, err
		}
		challengeHash, err := s.ChallengeHash(input.ProofInput.Challenge)
		if err != nil {
			return nil, err
		}
		result.ProofHash = proofHash
		result.PublicKeyHash = publicKeyHash
		result.ChallengeHash = challengeHash

		if len(input.ExpectedProofHash) > 0 && !bytes.Equal(input.ExpectedProofHash, proofHash) {
			result.HashesMatch = false
			result.Messages = append(result.Messages, "proof hash mismatch")
		}
		if len(input.ExpectedPublicKeyHash) > 0 && !bytes.Equal(input.ExpectedPublicKeyHash, publicKeyHash) {
			result.HashesMatch = false
			result.Messages = append(result.Messages, "public key hash mismatch")
		}
		if len(input.ExpectedChallengeHash) > 0 && !bytes.Equal(input.ExpectedChallengeHash, challengeHash) {
			result.HashesMatch = false
			result.Messages = append(result.Messages, "challenge hash mismatch")
		}
	}

	result.Valid = result.StructuralValid && result.HashesMatch
	if result.Valid && len(result.Messages) == 0 {
		result.Messages = append(result.Messages, "tmps envelope integrity verified")
	}
	return result, nil
}

func (s *Service) VerifyWithPlan(input *tmps.ProofInput, options *tmps.VerifyOptions) (*tmps.VerificationResult, error) {
	result, err := s.VerifyEnvelope(&tmps.VerificationInput{ProofInput: input})
	if err != nil {
		return nil, err
	}
	if options == nil {
		return result, nil
	}

	if options.ChallengeMaterial != nil {
		expectedChallenge, err := s.GenerateChallenge(options.ChallengeMaterial)
		if err != nil {
			return nil, err
		}
		result.GeneratedChallenge = expectedChallenge
		check := tmps.CheckResult{
			Name:  "generated_challenge_matches_input",
			Valid: input != nil && input.Challenge != nil && expectedChallenge.Cmp(input.Challenge) == 0,
		}
		if check.Valid {
			check.Message = "generated challenge matches input challenge"
		} else {
			check.Message = "generated challenge does not match input challenge"
			result.Valid = false
		}
		result.Checks = append(result.Checks, check)
	}

	if len(options.PairingChecks) > 0 {
		checks, err := tmps.VerifyPairingChecks(input, options.PairingChecks)
		if err != nil {
			return nil, err
		}
		result.Checks = append(result.Checks, checks...)
		for _, check := range checks {
			if !check.Valid {
				result.Valid = false
			}
		}
	}

	if result.Valid && len(result.Messages) == 0 {
		result.Messages = append(result.Messages, "tmps verification plan passed")
	}
	return result, nil
}

func (s *Service) ProofHash(input *tmps.ProofInput) ([]byte, error) {
	payload, err := s.MarshalProofInput(input)
	if err != nil {
		return nil, err
	}
	return tmps.HashBytes(s.hashAlgorithm, payload)
}

func (s *Service) PublicKeyHash(bundle *tmps.Bundle) ([]byte, error) {
	payload, err := s.MarshalBundle(bundle)
	if err != nil {
		return nil, err
	}
	return tmps.HashBytes(s.hashAlgorithm, payload)
}

func (s *Service) ChallengeHash(challenge *big.Int) ([]byte, error) {
	payload, err := s.MarshalChallenge(challenge)
	if err != nil {
		return nil, err
	}
	return tmps.HashBytes(s.hashAlgorithm, payload)
}

func (s *Service) Validate() error {
	if _, err := tmps.HashBytes(s.hashAlgorithm, nil); err != nil {
		return fmt.Errorf("invalid service configuration: %w", err)
	}
	return nil
}
