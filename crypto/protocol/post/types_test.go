package post

import "testing"

func TestValidateFunctions(t *testing.T) {
	if err := ValidateChallengeMaterial(nil); err == nil {
		t.Fatal("expected ValidateChallengeMaterial to fail")
	}
	if err := ValidateChallenge(nil); err == nil {
		t.Fatal("expected ValidateChallenge to fail")
	}
	if err := ValidateProofMaterial(nil); err == nil {
		t.Fatal("expected ValidateProofMaterial to fail")
	}
	if err := ValidateProof(nil); err == nil {
		t.Fatal("expected ValidateProof to fail")
	}
}
