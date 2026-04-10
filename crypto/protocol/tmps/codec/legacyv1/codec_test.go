package legacyv1

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/19231224lhr/CryptoArea/crypto/protocol/tmps"
	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

type goldenVectors struct {
	G1Scalar5Hex             string `json:"g1_scalar_5_hex"`
	G2Scalar7Hex             string `json:"g2_scalar_7_hex"`
	GTPairing35Hex           string `json:"gt_pairing_35_hex"`
	Challenge                string `json:"challenge_decimal"`
	ChallengeJSON            string `json:"challenge_json"`
	ChallengeMaterialJSON    string `json:"challenge_material_json"`
	GeneratedChallengeKeccak string `json:"generated_challenge_keccak_decimal"`
	GeneratedChallengeSHA256 string `json:"generated_challenge_sha256_decimal"`
	ProofInputJSON           string `json:"proof_input_json"`
	PkJSON                   string `json:"pk_json"`
	ProofKeccak256           string `json:"proof_keccak256"`
	PkKeccak256              string `json:"pk_keccak256"`
	ChallengeKeccak256       string `json:"challenge_keccak256"`
	ProofSHA256              string `json:"proof_sha256"`
	PkSHA256                 string `json:"pk_sha256"`
	ChallengeSHA256          string `json:"challenge_sha256"`
}

func TestGoldenVectorsMatchLegacyV1Codec(t *testing.T) {
	vectors := loadGoldenVectors(t)
	input := newGoldenProofInput(t)
	challengeMaterial := newGoldenChallengeMaterial(t)
	service := MustNewService()
	shaService := MustNewService(WithHashAlgorithm(tmps.HashAlgorithmSHA256))

	if got := EncodeG1(input.Pk.G1[0]); got != vectors.G1Scalar5Hex {
		t.Fatalf("unexpected G1 vector: got %s want %s", got, vectors.G1Scalar5Hex)
	}
	if got := EncodeG2(input.Pi.G2[0]); got != vectors.G2Scalar7Hex {
		t.Fatalf("unexpected G2 vector: got %s want %s", got, vectors.G2Scalar7Hex)
	}
	if got := EncodeGT(input.Pi.GT[0]); got != vectors.GTPairing35Hex {
		t.Fatalf("unexpected GT vector: got %s want %s", got, vectors.GTPairing35Hex)
	}
	if got := input.Challenge.String(); got != vectors.Challenge {
		t.Fatalf("unexpected challenge vector: got %s want %s", got, vectors.Challenge)
	}

	encoded, err := MarshalProofInput(input)
	if err != nil {
		t.Fatalf("MarshalProofInput failed: %v", err)
	}
	if string(encoded) != vectors.ProofInputJSON {
		t.Fatalf("unexpected proof input json: got %s want %s", string(encoded), vectors.ProofInputJSON)
	}
	pkJSON, err := MarshalBundle(input.Pk)
	if err != nil {
		t.Fatalf("MarshalBundle failed: %v", err)
	}
	if string(pkJSON) != vectors.PkJSON {
		t.Fatalf("unexpected pk json: got %s want %s", string(pkJSON), vectors.PkJSON)
	}
	challengeJSON, err := MarshalChallenge(input.Challenge)
	if err != nil {
		t.Fatalf("MarshalChallenge failed: %v", err)
	}
	if string(challengeJSON) != vectors.ChallengeJSON {
		t.Fatalf("unexpected challenge json: got %s want %s", string(challengeJSON), vectors.ChallengeJSON)
	}
	challengeMaterialJSON, err := service.MarshalChallengeMaterial(challengeMaterial)
	if err != nil {
		t.Fatalf("MarshalChallengeMaterial failed: %v", err)
	}
	if string(challengeMaterialJSON) != vectors.ChallengeMaterialJSON {
		t.Fatalf("unexpected challenge material json: got %s want %s", string(challengeMaterialJSON), vectors.ChallengeMaterialJSON)
	}
	generatedChallenge, err := service.GenerateChallenge(challengeMaterial)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	if generatedChallenge.String() != vectors.GeneratedChallengeKeccak {
		t.Fatalf("unexpected generated keccak challenge: got %s want %s", generatedChallenge.String(), vectors.GeneratedChallengeKeccak)
	}
	shaGeneratedChallenge, err := shaService.GenerateChallenge(challengeMaterial)
	if err != nil {
		t.Fatalf("GenerateChallenge sha256 failed: %v", err)
	}
	if shaGeneratedChallenge.String() != vectors.GeneratedChallengeSHA256 {
		t.Fatalf("unexpected generated sha256 challenge: got %s want %s", shaGeneratedChallenge.String(), vectors.GeneratedChallengeSHA256)
	}

	proofHash, err := service.ProofHash(input)
	if err != nil {
		t.Fatalf("ProofHash failed: %v", err)
	}
	if got := "0x" + hexEncode(proofHash); got != vectors.ProofKeccak256 {
		t.Fatalf("unexpected proof keccak256: got %s want %s", got, vectors.ProofKeccak256)
	}
	pkHash, err := service.PublicKeyHash(input.Pk)
	if err != nil {
		t.Fatalf("PublicKeyHash failed: %v", err)
	}
	if got := "0x" + hexEncode(pkHash); got != vectors.PkKeccak256 {
		t.Fatalf("unexpected pk keccak256: got %s want %s", got, vectors.PkKeccak256)
	}
	challengeHash, err := service.ChallengeHash(input.Challenge)
	if err != nil {
		t.Fatalf("ChallengeHash failed: %v", err)
	}
	if got := "0x" + hexEncode(challengeHash); got != vectors.ChallengeKeccak256 {
		t.Fatalf("unexpected challenge keccak256: got %s want %s", got, vectors.ChallengeKeccak256)
	}

	proofSHA, err := shaService.ProofHash(input)
	if err != nil {
		t.Fatalf("ProofHash sha256 failed: %v", err)
	}
	if got := "0x" + hexEncode(proofSHA); got != vectors.ProofSHA256 {
		t.Fatalf("unexpected proof sha256: got %s want %s", got, vectors.ProofSHA256)
	}
	pkSHA, err := shaService.PublicKeyHash(input.Pk)
	if err != nil {
		t.Fatalf("PublicKeyHash sha256 failed: %v", err)
	}
	if got := "0x" + hexEncode(pkSHA); got != vectors.PkSHA256 {
		t.Fatalf("unexpected pk sha256: got %s want %s", got, vectors.PkSHA256)
	}
	challengeSHA, err := shaService.ChallengeHash(input.Challenge)
	if err != nil {
		t.Fatalf("ChallengeHash sha256 failed: %v", err)
	}
	if got := "0x" + hexEncode(challengeSHA); got != vectors.ChallengeSHA256 {
		t.Fatalf("unexpected challenge sha256: got %s want %s", got, vectors.ChallengeSHA256)
	}

	decoded, err := UnmarshalProofInput(encoded)
	if err != nil {
		t.Fatalf("UnmarshalProofInput failed: %v", err)
	}
	assertProofInputsEqual(t, input, decoded)

	verifyResult, err := service.VerifyEnvelope(&tmps.VerificationInput{
		ProofInput:            input,
		ExpectedProofHash:     proofHash,
		ExpectedPublicKeyHash: pkHash,
		ExpectedChallengeHash: challengeHash,
	})
	if err != nil {
		t.Fatalf("VerifyEnvelope failed: %v", err)
	}
	if !verifyResult.Valid {
		t.Fatalf("expected VerifyEnvelope to succeed, messages: %v", verifyResult.Messages)
	}
}

func TestDecodeRejectsWrongLengthsAndNegativeScalars(t *testing.T) {
	if _, err := DecodeG1("0x01"); err == nil {
		t.Fatal("expected DecodeG1 to fail")
	}
	if _, err := decodeScalar("-1"); err == nil {
		t.Fatal("expected decodeScalar to fail on negative values")
	}
}

func TestServiceMarshalAndHashHelpers(t *testing.T) {
	input := newGoldenProofInput(t)
	material := newGoldenChallengeMaterial(t)
	service := MustNewService(WithHashAlgorithm(tmps.HashAlgorithmSHA256))

	pkJSON, err := service.MarshalBundle(input.Pk)
	if err != nil {
		t.Fatalf("MarshalBundle failed: %v", err)
	}
	pk, err := service.UnmarshalBundle(pkJSON)
	if err != nil {
		t.Fatalf("UnmarshalBundle failed: %v", err)
	}
	assertBundlesEqual(t, input.Pk, pk)

	challengeJSON, err := service.MarshalChallenge(input.Challenge)
	if err != nil {
		t.Fatalf("MarshalChallenge failed: %v", err)
	}
	challenge, err := service.UnmarshalChallenge(challengeJSON)
	if err != nil {
		t.Fatalf("UnmarshalChallenge failed: %v", err)
	}
	if challenge.Cmp(input.Challenge) != 0 {
		t.Fatalf("challenge mismatch: got %s want %s", challenge.String(), input.Challenge.String())
	}

	materialJSON, err := service.MarshalChallengeMaterial(material)
	if err != nil {
		t.Fatalf("MarshalChallengeMaterial failed: %v", err)
	}
	if len(materialJSON) == 0 {
		t.Fatal("expected challenge material json")
	}
	generatedChallenge, err := service.GenerateChallenge(material)
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}
	if err := tmps.ValidateChallenge(generatedChallenge); err != nil {
		t.Fatalf("generated challenge validation failed: %v", err)
	}

	okResult, err := service.VerifyEnvelope(&tmps.VerificationInput{ProofInput: input})
	if err != nil {
		t.Fatalf("VerifyEnvelope failed: %v", err)
	}
	if !okResult.Valid {
		t.Fatalf("expected VerifyEnvelope without expected hashes to succeed, messages: %v", okResult.Messages)
	}

	badResult, err := service.VerifyEnvelope(&tmps.VerificationInput{
		ProofInput:            input,
		ExpectedProofHash:     []byte{0x01},
		ExpectedPublicKeyHash: []byte{0x02},
		ExpectedChallengeHash: []byte{0x03},
	})
	if err != nil {
		t.Fatalf("VerifyEnvelope with bad hashes failed unexpectedly: %v", err)
	}
	if badResult.Valid || badResult.HashesMatch {
		t.Fatal("expected VerifyEnvelope with mismatched hashes to fail integrity checks")
	}

	if _, err := NewService(WithHashAlgorithm("unknown")); err == nil {
		t.Fatal("expected NewService to reject unknown hash algorithm")
	}
}

func loadGoldenVectors(t *testing.T) *goldenVectors {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "legacyv1_golden.json")
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

func newGoldenProofInput(t *testing.T) *tmps.ProofInput {
	t.Helper()
	g1 := bn254.NewG1()
	g2 := bn254.NewG2()
	engine := bn254.NewEngine()

	g1Scalar5 := g1.New()
	g1.MulScalarBig(g1Scalar5, g1.One(), big.NewInt(5))
	g2Scalar7 := g2.New()
	g2.MulScalarBig(g2Scalar7, g2.One(), big.NewInt(7))
	gtPairing35 := engine.AddPair(g1Scalar5, g2Scalar7).Result()

	return &tmps.ProofInput{
		Pk: &tmps.Bundle{
			G1:      []*bn254.PointG1{g1Scalar5},
			Scalars: []*big.Int{big.NewInt(11)},
		},
		Challenge: mustBigInt("123456789012345678901234567890"),
		Pi: &tmps.Bundle{
			G2:      []*bn254.PointG2{g2Scalar7},
			GT:      []*bn254.E{gtPairing35},
			Scalars: []*big.Int{big.NewInt(17)},
		},
		Vk: &tmps.Bundle{
			G1:      []*bn254.PointG1{g1.One()},
			G2:      []*bn254.PointG2{g2.One()},
			Scalars: []*big.Int{big.NewInt(23)},
		},
	}
}

func newGoldenChallengeMaterial(t *testing.T) *tmps.ChallengeMaterial {
	t.Helper()
	input := newGoldenProofInput(t)
	return &tmps.ChallengeMaterial{
		Pk:      input.Pk,
		Vk:      input.Vk,
		Context: []byte("tmps-legacyv1"),
		Nonce:   []byte{0x01, 0x02, 0x03},
	}
}

func assertProofInputsEqual(t *testing.T, want *tmps.ProofInput, got *tmps.ProofInput) {
	t.Helper()
	if want.Challenge.Cmp(got.Challenge) != 0 {
		t.Fatalf("challenge mismatch: got %s want %s", got.Challenge.String(), want.Challenge.String())
	}
	assertBundlesEqual(t, want.Pk, got.Pk)
	assertBundlesEqual(t, want.Pi, got.Pi)
	assertBundlesEqual(t, want.Vk, got.Vk)
}

func assertBundlesEqual(t *testing.T, want *tmps.Bundle, got *tmps.Bundle) {
	t.Helper()
	if (want == nil) != (got == nil) {
		t.Fatalf("bundle nil mismatch")
	}
	if want == nil {
		return
	}
	if len(want.G1) != len(got.G1) || len(want.G2) != len(got.G2) || len(want.GT) != len(got.GT) || len(want.Scalars) != len(got.Scalars) {
		t.Fatalf("bundle length mismatch")
	}
	g1 := bn254.NewG1()
	g2 := bn254.NewG2()
	gt := bn254.NewGT()
	for i := range want.G1 {
		if !g1.Equal(want.G1[i], got.G1[i]) {
			t.Fatalf("g1[%d] mismatch", i)
		}
	}
	for i := range want.G2 {
		if !g2.Equal(want.G2[i], got.G2[i]) {
			t.Fatalf("g2[%d] mismatch", i)
		}
	}
	for i := range want.GT {
		if !gt.New().Set(want.GT[i]).Equal(got.GT[i]) {
			t.Fatalf("gt[%d] mismatch", i)
		}
	}
	for i := range want.Scalars {
		if want.Scalars[i].Cmp(got.Scalars[i]) != 0 {
			t.Fatalf("scalar[%d] mismatch", i)
		}
	}
}

func mustBigInt(value string) *big.Int {
	out, ok := new(big.Int).SetString(value, 10)
	if !ok {
		panic("invalid big.Int literal: " + value)
	}
	return out
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

func TestMarshalProofInputIsStableAcrossRoundTrips(t *testing.T) {
	input := newGoldenProofInput(t)
	first, err := MarshalProofInput(input)
	if err != nil {
		t.Fatalf("MarshalProofInput failed: %v", err)
	}
	decoded, err := UnmarshalProofInput(first)
	if err != nil {
		t.Fatalf("UnmarshalProofInput failed: %v", err)
	}
	second, err := MarshalProofInput(decoded)
	if err != nil {
		t.Fatalf("MarshalProofInput second failed: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("marshal output changed across round-trip")
	}
}
