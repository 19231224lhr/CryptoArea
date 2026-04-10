package post

import "fmt"

type Option func(*service)

type service struct {
	profile ProfileName
}

func NewService(options ...Option) (Service, error) {
	svc := &service{profile: ProfileStrictV1}
	for _, option := range options {
		option(svc)
	}
	if err := validateProfile(svc.profile); err != nil {
		return nil, err
	}
	return svc, nil
}

func MustNewService(options ...Option) Service {
	svc, err := NewService(options...)
	if err != nil {
		panic(err)
	}
	return svc
}

func WithProfile(profile ProfileName) Option {
	return func(svc *service) {
		svc.profile = profile
	}
}

func (s *service) Profile() ProfileName {
	return s.profile
}

func (s *service) MarshalChallengeMaterial(material *ChallengeMaterial) ([]byte, error) {
	return MarshalChallengeMaterial(material)
}

func (s *service) UnmarshalChallengeMaterial(data []byte) (*ChallengeMaterial, error) {
	return UnmarshalChallengeMaterial(data)
}

func (s *service) MarshalProofMaterial(material *ProofMaterial) ([]byte, error) {
	return MarshalProofMaterial(material)
}

func (s *service) UnmarshalProofMaterial(data []byte) (*ProofMaterial, error) {
	return UnmarshalProofMaterial(data)
}

func (s *service) MarshalChallenge(challenge *Challenge) ([]byte, error) {
	return MarshalChallenge(challenge)
}

func (s *service) UnmarshalChallenge(data []byte) (*Challenge, error) {
	return UnmarshalChallenge(data)
}

func (s *service) MarshalProof(proof *Proof) ([]byte, error) {
	return MarshalProof(proof)
}

func (s *service) UnmarshalProof(data []byte) (*Proof, error) {
	return UnmarshalProof(data)
}

func (s *service) GenerateChallenge(material *ChallengeMaterial) (*Challenge, error) {
	if err := ValidateChallengeMaterial(material); err != nil {
		return nil, err
	}
	payload, err := MarshalChallengeMaterial(material)
	if err != nil {
		return nil, err
	}
	digest, err := challengeDigest(s.profile, payload)
	if err != nil {
		return nil, err
	}
	return &Challenge{
		Profile: s.profile,
		Digest:  digest,
	}, nil
}

func (s *service) Prove(material *ProofMaterial) (*Proof, error) {
	if err := ValidateProofMaterial(material); err != nil {
		return nil, err
	}
	if material.Challenge.Profile != s.profile {
		return nil, fmt.Errorf("challenge profile mismatch: got %s want %s", material.Challenge.Profile, s.profile)
	}
	witnessDigestValue, err := witnessDigest(s.profile, material.Witness)
	if err != nil {
		return nil, err
	}
	responseInput := make([]byte, 0, len(material.Challenge.Digest)+len(witnessDigestValue)+len(material.Metadata))
	responseInput = append(responseInput, material.Challenge.Digest...)
	responseInput = append(responseInput, witnessDigestValue...)
	responseInput = append(responseInput, material.Metadata...)
	responseDigestValue, err := responseDigest(s.profile, material.AuthenticatorKey, responseInput)
	if err != nil {
		return nil, err
	}
	return &Proof{
		Profile:         s.profile,
		ChallengeDigest: cloneBytes(material.Challenge.Digest),
		WitnessDigest:   witnessDigestValue,
		ResponseDigest:  responseDigestValue,
		Metadata:        cloneBytes(material.Metadata),
	}, nil
}

func (s *service) Verify(input *VerificationInput) (*VerificationResult, error) {
	if input == nil {
		return nil, fmt.Errorf("verification input must not be nil")
	}
	result := &VerificationResult{StructuralValid: true, ChallengeMatches: true, ResponseMatches: true}
	if err := ValidateChallenge(input.Challenge); err != nil {
		result.StructuralValid = false
		result.Messages = append(result.Messages, err.Error())
	}
	if err := ValidateProof(input.Proof); err != nil {
		result.StructuralValid = false
		result.Messages = append(result.Messages, err.Error())
	}
	if len(input.Witness) == 0 {
		result.StructuralValid = false
		result.Messages = append(result.Messages, "witness must not be empty")
	}
	if len(input.AuthenticatorKey) == 0 {
		result.StructuralValid = false
		result.Messages = append(result.Messages, "authenticator key must not be empty")
	}
	if !result.StructuralValid {
		result.Valid = false
		return result, nil
	}
	if input.Challenge.Profile != s.profile || input.Proof.Profile != s.profile {
		result.Valid = false
		result.StructuralValid = false
		result.Messages = append(result.Messages, "profile mismatch")
		return result, nil
	}

	expectedWitnessDigest, err := witnessDigest(s.profile, input.Witness)
	if err != nil {
		return nil, err
	}
	result.ExpectedWitness = expectedWitnessDigest

	if string(expectedWitnessDigest) != string(input.Proof.WitnessDigest) {
		result.ResponseMatches = false
		result.Messages = append(result.Messages, "witness digest mismatch")
	}

	if string(input.Challenge.Digest) != string(input.Proof.ChallengeDigest) {
		result.ChallengeMatches = false
		result.Messages = append(result.Messages, "challenge digest mismatch")
	}
	result.ExpectedChallenge = cloneBytes(input.Challenge.Digest)

	responseInput := make([]byte, 0, len(input.Challenge.Digest)+len(expectedWitnessDigest)+len(input.Proof.Metadata))
	responseInput = append(responseInput, input.Challenge.Digest...)
	responseInput = append(responseInput, expectedWitnessDigest...)
	responseInput = append(responseInput, input.Proof.Metadata...)
	expectedResponseDigest, err := responseDigest(s.profile, input.AuthenticatorKey, responseInput)
	if err != nil {
		return nil, err
	}
	result.ExpectedResponse = expectedResponseDigest
	if string(expectedResponseDigest) != string(input.Proof.ResponseDigest) {
		result.ResponseMatches = false
		result.Messages = append(result.Messages, "response digest mismatch")
	}

	result.Valid = result.StructuralValid && result.ChallengeMatches && result.ResponseMatches
	if result.Valid && len(result.Messages) == 0 {
		result.Messages = append(result.Messages, "post proof verified")
	}
	return result, nil
}

func (s *service) ChallengeHash(challenge *Challenge) ([]byte, error) {
	payload, err := MarshalChallenge(challenge)
	if err != nil {
		return nil, err
	}
	return challengeDigest(s.profile, payload)
}

func (s *service) ProofHash(proof *Proof) ([]byte, error) {
	payload, err := MarshalProof(proof)
	if err != nil {
		return nil, err
	}
	return challengeDigest(s.profile, payload)
}
