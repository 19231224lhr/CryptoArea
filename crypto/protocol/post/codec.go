package post

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/19231224lhr/CryptoArea/crypto/encoding/canonical"
)

type wireChallengeMaterial struct {
	Commitment string `json:"commitment"`
	TimeAnchor string `json:"time_anchor"`
	Nonce      string `json:"nonce"`
	Context    string `json:"context"`
	Metadata   string `json:"metadata,omitempty"`
}

type wireChallenge struct {
	Profile string `json:"profile"`
	Digest  string `json:"digest"`
}

type wireProofMaterial struct {
	Challenge        *wireChallenge `json:"challenge"`
	Witness          string         `json:"witness"`
	AuthenticatorKey string         `json:"authenticator_key"`
	Metadata         string         `json:"metadata,omitempty"`
}

type wireProof struct {
	Profile         string `json:"profile"`
	ChallengeDigest string `json:"challenge_digest"`
	WitnessDigest   string `json:"witness_digest"`
	ResponseDigest  string `json:"response_digest"`
	Metadata        string `json:"metadata,omitempty"`
}

func MarshalChallengeMaterial(material *ChallengeMaterial) ([]byte, error) {
	wire, err := toWireChallengeMaterial(material)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalChallengeMaterial(data []byte) (*ChallengeMaterial, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("challenge material bytes must not be empty")
	}
	var wire wireChallengeMaterial
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return fromWireChallengeMaterial(&wire)
}

func MarshalChallenge(challenge *Challenge) ([]byte, error) {
	wire, err := toWireChallenge(challenge)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalChallenge(data []byte) (*Challenge, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("challenge bytes must not be empty")
	}
	var wire wireChallenge
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return fromWireChallenge(&wire)
}

func MarshalProofMaterial(material *ProofMaterial) ([]byte, error) {
	wire, err := toWireProofMaterial(material)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalProofMaterial(data []byte) (*ProofMaterial, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("proof material bytes must not be empty")
	}
	var wire wireProofMaterial
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return fromWireProofMaterial(&wire)
}

func MarshalProof(proof *Proof) ([]byte, error) {
	wire, err := toWireProof(proof)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalProof(data []byte) (*Proof, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("proof bytes must not be empty")
	}
	var wire wireProof
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return fromWireProof(&wire)
}

func toWireChallengeMaterial(material *ChallengeMaterial) (*wireChallengeMaterial, error) {
	if err := ValidateChallengeMaterial(material); err != nil {
		return nil, err
	}
	return &wireChallengeMaterial{
		Commitment: encodeHex(material.Commitment),
		TimeAnchor: encodeHex(material.TimeAnchor),
		Nonce:      encodeHex(material.Nonce),
		Context:    encodeHex(material.Context),
		Metadata:   encodeOptionalHex(material.Metadata),
	}, nil
}

func fromWireChallengeMaterial(wire *wireChallengeMaterial) (*ChallengeMaterial, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire challenge material must not be nil")
	}
	material := &ChallengeMaterial{}
	var err error
	if material.Commitment, err = decodeHex(wire.Commitment); err != nil {
		return nil, err
	}
	if material.TimeAnchor, err = decodeHex(wire.TimeAnchor); err != nil {
		return nil, err
	}
	if material.Nonce, err = decodeHex(wire.Nonce); err != nil {
		return nil, err
	}
	if material.Context, err = decodeHex(wire.Context); err != nil {
		return nil, err
	}
	if material.Metadata, err = decodeOptionalHex(wire.Metadata); err != nil {
		return nil, err
	}
	if err := ValidateChallengeMaterial(material); err != nil {
		return nil, err
	}
	return material, nil
}

func toWireChallenge(challenge *Challenge) (*wireChallenge, error) {
	if err := ValidateChallenge(challenge); err != nil {
		return nil, err
	}
	return &wireChallenge{
		Profile: string(challenge.Profile),
		Digest:  encodeHex(challenge.Digest),
	}, nil
}

func fromWireChallenge(wire *wireChallenge) (*Challenge, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire challenge must not be nil")
	}
	digest, err := decodeHex(wire.Digest)
	if err != nil {
		return nil, err
	}
	challenge := &Challenge{
		Profile: ProfileName(wire.Profile),
		Digest:  digest,
	}
	if err := ValidateChallenge(challenge); err != nil {
		return nil, err
	}
	return challenge, nil
}

func toWireProofMaterial(material *ProofMaterial) (*wireProofMaterial, error) {
	if err := ValidateProofMaterial(material); err != nil {
		return nil, err
	}
	challenge, err := toWireChallenge(material.Challenge)
	if err != nil {
		return nil, err
	}
	return &wireProofMaterial{
		Challenge:        challenge,
		Witness:          encodeHex(material.Witness),
		AuthenticatorKey: encodeHex(material.AuthenticatorKey),
		Metadata:         encodeOptionalHex(material.Metadata),
	}, nil
}

func fromWireProofMaterial(wire *wireProofMaterial) (*ProofMaterial, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire proof material must not be nil")
	}
	challenge, err := fromWireChallenge(wire.Challenge)
	if err != nil {
		return nil, err
	}
	witness, err := decodeHex(wire.Witness)
	if err != nil {
		return nil, err
	}
	authenticatorKey, err := decodeHex(wire.AuthenticatorKey)
	if err != nil {
		return nil, err
	}
	metadata, err := decodeOptionalHex(wire.Metadata)
	if err != nil {
		return nil, err
	}
	material := &ProofMaterial{
		Challenge:        challenge,
		Witness:          witness,
		AuthenticatorKey: authenticatorKey,
		Metadata:         metadata,
	}
	if err := ValidateProofMaterial(material); err != nil {
		return nil, err
	}
	return material, nil
}

func toWireProof(proof *Proof) (*wireProof, error) {
	if err := ValidateProof(proof); err != nil {
		return nil, err
	}
	return &wireProof{
		Profile:         string(proof.Profile),
		ChallengeDigest: encodeHex(proof.ChallengeDigest),
		WitnessDigest:   encodeHex(proof.WitnessDigest),
		ResponseDigest:  encodeHex(proof.ResponseDigest),
		Metadata:        encodeOptionalHex(proof.Metadata),
	}, nil
}

func fromWireProof(wire *wireProof) (*Proof, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire proof must not be nil")
	}
	challengeDigest, err := decodeHex(wire.ChallengeDigest)
	if err != nil {
		return nil, err
	}
	witnessDigest, err := decodeHex(wire.WitnessDigest)
	if err != nil {
		return nil, err
	}
	responseDigest, err := decodeHex(wire.ResponseDigest)
	if err != nil {
		return nil, err
	}
	metadata, err := decodeOptionalHex(wire.Metadata)
	if err != nil {
		return nil, err
	}
	proof := &Proof{
		Profile:         ProfileName(wire.Profile),
		ChallengeDigest: challengeDigest,
		WitnessDigest:   witnessDigest,
		ResponseDigest:  responseDigest,
		Metadata:        metadata,
	}
	if err := ValidateProof(proof); err != nil {
		return nil, err
	}
	return proof, nil
}

func encodeHex(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

func encodeOptionalHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return encodeHex(data)
}

func decodeHex(value string) ([]byte, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	if trimmed == "" {
		return nil, fmt.Errorf("hex value must not be empty")
	}
	return hex.DecodeString(trimmed)
}

func decodeOptionalHex(value string) ([]byte, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	return decodeHex(value)
}
