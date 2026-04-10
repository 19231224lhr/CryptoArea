package post

import "fmt"

type ProfileName string

const (
	ProfileStrictV1       ProfileName = "post-strict-v1"
	ProfileLegacyCompatV1 ProfileName = "post-legacycompat-v1"
)

type ChallengeMaterial struct {
	Commitment []byte
	TimeAnchor []byte
	Nonce      []byte
	Context    []byte
	Metadata   []byte
}

type Challenge struct {
	Profile ProfileName
	Digest  []byte
}

type ProofMaterial struct {
	Challenge        *Challenge
	Witness          []byte
	AuthenticatorKey []byte
	Metadata         []byte
}

type Proof struct {
	Profile         ProfileName
	ChallengeDigest []byte
	WitnessDigest   []byte
	ResponseDigest  []byte
	Metadata        []byte
}

type VerificationInput struct {
	Challenge        *Challenge
	Proof            *Proof
	Witness          []byte
	AuthenticatorKey []byte
}

type VerificationResult struct {
	Valid             bool
	StructuralValid   bool
	ChallengeMatches  bool
	ResponseMatches   bool
	ExpectedChallenge []byte
	ExpectedWitness   []byte
	ExpectedResponse  []byte
	Messages          []string
}

type Service interface {
	Profile() ProfileName
	MarshalChallengeMaterial(material *ChallengeMaterial) ([]byte, error)
	UnmarshalChallengeMaterial(data []byte) (*ChallengeMaterial, error)
	MarshalProofMaterial(material *ProofMaterial) ([]byte, error)
	UnmarshalProofMaterial(data []byte) (*ProofMaterial, error)
	MarshalChallenge(challenge *Challenge) ([]byte, error)
	UnmarshalChallenge(data []byte) (*Challenge, error)
	MarshalProof(proof *Proof) ([]byte, error)
	UnmarshalProof(data []byte) (*Proof, error)
	GenerateChallenge(material *ChallengeMaterial) (*Challenge, error)
	Prove(material *ProofMaterial) (*Proof, error)
	Verify(input *VerificationInput) (*VerificationResult, error)
	ChallengeHash(challenge *Challenge) ([]byte, error)
	ProofHash(proof *Proof) ([]byte, error)
}

func ValidateChallengeMaterial(material *ChallengeMaterial) error {
	if material == nil {
		return fmt.Errorf("challenge material must not be nil")
	}
	if len(material.Commitment) == 0 {
		return fmt.Errorf("commitment must not be empty")
	}
	if len(material.TimeAnchor) == 0 {
		return fmt.Errorf("time anchor must not be empty")
	}
	if len(material.Nonce) == 0 {
		return fmt.Errorf("nonce must not be empty")
	}
	if len(material.Context) == 0 {
		return fmt.Errorf("context must not be empty")
	}
	return nil
}

func ValidateChallenge(challenge *Challenge) error {
	if challenge == nil {
		return fmt.Errorf("challenge must not be nil")
	}
	if err := validateProfile(challenge.Profile); err != nil {
		return err
	}
	if len(challenge.Digest) == 0 {
		return fmt.Errorf("challenge digest must not be empty")
	}
	return nil
}

func ValidateProofMaterial(material *ProofMaterial) error {
	if material == nil {
		return fmt.Errorf("proof material must not be nil")
	}
	if err := ValidateChallenge(material.Challenge); err != nil {
		return err
	}
	if len(material.Witness) == 0 {
		return fmt.Errorf("witness must not be empty")
	}
	if len(material.AuthenticatorKey) == 0 {
		return fmt.Errorf("authenticator key must not be empty")
	}
	return nil
}

func ValidateProof(proof *Proof) error {
	if proof == nil {
		return fmt.Errorf("proof must not be nil")
	}
	if err := validateProfile(proof.Profile); err != nil {
		return err
	}
	if len(proof.ChallengeDigest) == 0 {
		return fmt.Errorf("proof challenge digest must not be empty")
	}
	if len(proof.WitnessDigest) == 0 {
		return fmt.Errorf("proof witness digest must not be empty")
	}
	if len(proof.ResponseDigest) == 0 {
		return fmt.Errorf("proof response digest must not be empty")
	}
	return nil
}

func validateProfile(profile ProfileName) error {
	switch profile {
	case ProfileStrictV1, ProfileLegacyCompatV1:
		return nil
	default:
		return fmt.Errorf("unsupported post profile: %s", profile)
	}
}

func cloneBytes(data []byte) []byte {
	if len(data) == 0 {
		return nil
	}
	out := make([]byte, len(data))
	copy(out, data)
	return out
}
