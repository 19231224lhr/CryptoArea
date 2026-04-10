package post

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenVectors struct {
	StrictChallengeMaterialJSON string `json:"strict_challenge_material_json"`
	StrictChallengeJSON         string `json:"strict_challenge_json"`
	StrictProofMaterialJSON     string `json:"strict_proof_material_json"`
	StrictProofJSON             string `json:"strict_proof_json"`
	StrictChallengeHash         string `json:"strict_challenge_hash"`
	StrictProofHash             string `json:"strict_proof_hash"`
	LegacyChallengeMaterialJSON string `json:"legacy_challenge_material_json"`
	LegacyChallengeJSON         string `json:"legacy_challenge_json"`
	LegacyProofMaterialJSON     string `json:"legacy_proof_material_json"`
	LegacyProofJSON             string `json:"legacy_proof_json"`
	LegacyChallengeHash         string `json:"legacy_challenge_hash"`
	LegacyProofHash             string `json:"legacy_proof_hash"`
}

func TestGoldenVectorsMatchServices(t *testing.T) {
	vectors := loadGoldenVectors(t)
	strictMaterial, strictProofMaterial := buildMaterials(ProfileStrictV1)
	legacyMaterial, legacyProofMaterial := buildMaterials(ProfileLegacyCompatV1)

	strictService := MustNewService()
	legacyService := MustNewService(WithProfile(ProfileLegacyCompatV1))

	assertChallengeMaterialRoundTrip(t, strictService, strictMaterial, vectors.StrictChallengeMaterialJSON)
	assertProofFlow(t, strictService, strictMaterial, strictProofMaterial, vectors.StrictChallengeJSON, vectors.StrictProofMaterialJSON, vectors.StrictProofJSON, vectors.StrictChallengeHash, vectors.StrictProofHash)

	assertChallengeMaterialRoundTrip(t, legacyService, legacyMaterial, vectors.LegacyChallengeMaterialJSON)
	assertProofFlow(t, legacyService, legacyMaterial, legacyProofMaterial, vectors.LegacyChallengeJSON, vectors.LegacyProofMaterialJSON, vectors.LegacyProofJSON, vectors.LegacyChallengeHash, vectors.LegacyProofHash)
}

func assertChallengeMaterialRoundTrip(t *testing.T, service Service, material *ChallengeMaterial, wantJSON string) {
	t.Helper()
	payload, err := service.MarshalChallengeMaterial(material)
	if err != nil {
		t.Fatalf("MarshalChallengeMaterial failed: %v", err)
	}
	if string(payload) != wantJSON {
		t.Fatalf("unexpected challenge material json: got %s want %s", string(payload), wantJSON)
	}
	roundTrip, err := service.UnmarshalChallengeMaterial(payload)
	if err != nil {
		t.Fatalf("UnmarshalChallengeMaterial failed: %v", err)
	}
	if !bytes.Equal(roundTrip.Commitment, material.Commitment) || !bytes.Equal(roundTrip.TimeAnchor, material.TimeAnchor) || !bytes.Equal(roundTrip.Nonce, material.Nonce) || !bytes.Equal(roundTrip.Context, material.Context) || !bytes.Equal(roundTrip.Metadata, material.Metadata) {
		t.Fatal("challenge material round-trip mismatch")
	}
}

func assertProofFlow(t *testing.T, service Service, challengeMaterial *ChallengeMaterial, proofMaterial *ProofMaterial, wantChallengeJSON string, wantProofMaterialJSON string, wantProofJSON string, wantChallengeHash string, wantProofHash string) {
	t.Helper()
	challenge, err := service.GenerateChallenge(challengeMaterial)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	challengeJSON, err := service.MarshalChallenge(challenge)
	if err != nil {
		t.Fatalf("MarshalChallenge failed: %v", err)
	}
	if string(challengeJSON) != wantChallengeJSON {
		t.Fatalf("unexpected challenge json: got %s want %s", string(challengeJSON), wantChallengeJSON)
	}

	proofMaterial.Challenge = challenge
	proofMaterialJSON, err := service.MarshalProofMaterial(proofMaterial)
	if err != nil {
		t.Fatalf("MarshalProofMaterial failed: %v", err)
	}
	if string(proofMaterialJSON) != wantProofMaterialJSON {
		t.Fatalf("unexpected proof material json: got %s want %s", string(proofMaterialJSON), wantProofMaterialJSON)
	}

	proof, err := service.Prove(proofMaterial)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}
	proofJSON, err := service.MarshalProof(proof)
	if err != nil {
		t.Fatalf("MarshalProof failed: %v", err)
	}
	if string(proofJSON) != wantProofJSON {
		t.Fatalf("unexpected proof json: got %s want %s", string(proofJSON), wantProofJSON)
	}

	challengeHash, err := service.ChallengeHash(challenge)
	if err != nil {
		t.Fatalf("ChallengeHash failed: %v", err)
	}
	if "0x"+hexEncode(challengeHash) != wantChallengeHash {
		t.Fatalf("unexpected challenge hash: got 0x%s want %s", hexEncode(challengeHash), wantChallengeHash)
	}
	proofHash, err := service.ProofHash(proof)
	if err != nil {
		t.Fatalf("ProofHash failed: %v", err)
	}
	if "0x"+hexEncode(proofHash) != wantProofHash {
		t.Fatalf("unexpected proof hash: got 0x%s want %s", hexEncode(proofHash), wantProofHash)
	}

	result, err := service.Verify(&VerificationInput{
		Challenge:        challenge,
		Proof:            proof,
		Witness:          proofMaterial.Witness,
		AuthenticatorKey: proofMaterial.AuthenticatorKey,
	})
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !result.Valid {
		t.Fatalf("expected proof verification to succeed, messages: %v", result.Messages)
	}

	badResult, err := service.Verify(&VerificationInput{
		Challenge:        challenge,
		Proof:            proof,
		Witness:          []byte("tampered-witness"),
		AuthenticatorKey: proofMaterial.AuthenticatorKey,
	})
	if err != nil {
		t.Fatalf("Verify(tampered) failed: %v", err)
	}
	if badResult.Valid {
		t.Fatal("expected tampered proof verification to fail")
	}
}

func loadGoldenVectors(t *testing.T) *goldenVectors {
	t.Helper()
	path := filepath.Join("testdata", "reference_v1_golden.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var vectors goldenVectors
	if err := json.Unmarshal(payload, &vectors); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	return &vectors
}

func buildMaterials(profile ProfileName) (*ChallengeMaterial, *ProofMaterial) {
	material := &ChallengeMaterial{
		Commitment: []byte("commitment-root"),
		TimeAnchor: []byte("time-anchor"),
		Nonce:      []byte{0x01, 0x02, 0x03},
		Context:    []byte("post-context"),
		Metadata:   []byte("meta"),
	}
	proofMaterial := &ProofMaterial{
		Challenge:        &Challenge{Profile: profile, Digest: []byte("placeholder")},
		Witness:          []byte("witness-bytes"),
		AuthenticatorKey: []byte("authenticator-key-1234567890"),
		Metadata:         []byte("proof-meta"),
	}
	return material, proofMaterial
}

func hexEncode(raw []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}
