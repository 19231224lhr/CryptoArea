package legacyv1

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/19231224lhr/CryptoArea/crypto/encoding/canonical"
	"github.com/19231224lhr/CryptoArea/crypto/protocol/tmps"
	"github.com/19231224lhr/CryptoArea/crypto/types/curve/bn254"
)

type Bundle struct {
	G1      []string `json:"g1,omitempty"`
	G2      []string `json:"g2,omitempty"`
	GT      []string `json:"gt,omitempty"`
	Scalars []string `json:"scalars,omitempty"`
}

type ProofInput struct {
	Pk        *Bundle `json:"pk,omitempty"`
	Challenge string  `json:"challenge"`
	Pi        *Bundle `json:"pi,omitempty"`
	Vk        *Bundle `json:"vk,omitempty"`
}

type Challenge struct {
	Challenge string `json:"challenge"`
}

type ChallengeMaterial struct {
	Pk      *Bundle `json:"pk,omitempty"`
	Vk      *Bundle `json:"vk,omitempty"`
	Context string  `json:"context"`
	Nonce   string  `json:"nonce"`
}

func MarshalProofInput(input *tmps.ProofInput) ([]byte, error) {
	if input == nil {
		return nil, fmt.Errorf("proof input must not be nil")
	}
	wire, err := ToWireProofInput(input)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func MarshalBundle(bundle *tmps.Bundle) ([]byte, error) {
	wire, err := ToWireBundle(bundle)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalBundle(data []byte) (*tmps.Bundle, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("bundle payload must not be empty")
	}
	var wire Bundle
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return FromWireBundle(&wire)
}

func MarshalChallenge(challenge *big.Int) ([]byte, error) {
	if challenge == nil {
		return nil, fmt.Errorf("challenge must not be nil")
	}
	return canonical.Marshal(&Challenge{Challenge: encodeScalar(challenge)})
}

func MarshalChallengeMaterial(material *tmps.ChallengeMaterial) ([]byte, error) {
	wire, err := ToWireChallengeMaterial(material)
	if err != nil {
		return nil, err
	}
	return canonical.Marshal(wire)
}

func UnmarshalChallenge(data []byte) (*big.Int, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("challenge payload must not be empty")
	}
	var wire Challenge
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return decodeScalar(wire.Challenge)
}

func UnmarshalChallengeMaterial(data []byte) (*tmps.ChallengeMaterial, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("challenge material payload must not be empty")
	}
	var wire ChallengeMaterial
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return FromWireChallengeMaterial(&wire)
}

func UnmarshalProofInput(data []byte) (*tmps.ProofInput, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("proof input payload must not be empty")
	}
	var wire ProofInput
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	return FromWireProofInput(&wire)
}

func ToWireProofInput(input *tmps.ProofInput) (*ProofInput, error) {
	if input == nil {
		return nil, fmt.Errorf("proof input must not be nil")
	}
	if input.Challenge == nil {
		return nil, fmt.Errorf("challenge must not be nil")
	}
	pk, err := ToWireBundle(input.Pk)
	if err != nil {
		return nil, err
	}
	pi, err := ToWireBundle(input.Pi)
	if err != nil {
		return nil, err
	}
	vk, err := ToWireBundle(input.Vk)
	if err != nil {
		return nil, err
	}
	return &ProofInput{
		Pk:        pk,
		Challenge: encodeScalar(input.Challenge),
		Pi:        pi,
		Vk:        vk,
	}, nil
}

func ToWireChallengeMaterial(material *tmps.ChallengeMaterial) (*ChallengeMaterial, error) {
	if material == nil {
		return nil, fmt.Errorf("challenge material must not be nil")
	}
	pk, err := ToWireBundle(material.Pk)
	if err != nil {
		return nil, err
	}
	vk, err := ToWireBundle(material.Vk)
	if err != nil {
		return nil, err
	}
	return &ChallengeMaterial{
		Pk:      pk,
		Vk:      vk,
		Context: encodeHexBytes(material.Context),
		Nonce:   encodeHexBytes(material.Nonce),
	}, nil
}

func FromWireChallengeMaterial(wire *ChallengeMaterial) (*tmps.ChallengeMaterial, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire challenge material must not be nil")
	}
	pk, err := FromWireBundle(wire.Pk)
	if err != nil {
		return nil, fmt.Errorf("decode pk: %w", err)
	}
	vk, err := FromWireBundle(wire.Vk)
	if err != nil {
		return nil, fmt.Errorf("decode vk: %w", err)
	}
	context, err := decodeHexBytes(wire.Context, -1)
	if err != nil {
		return nil, fmt.Errorf("decode context: %w", err)
	}
	nonce, err := decodeHexBytes(wire.Nonce, -1)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	return &tmps.ChallengeMaterial{
		Pk:      pk,
		Vk:      vk,
		Context: context,
		Nonce:   nonce,
	}, nil
}

func FromWireProofInput(wire *ProofInput) (*tmps.ProofInput, error) {
	if wire == nil {
		return nil, fmt.Errorf("wire proof input must not be nil")
	}
	challenge, err := decodeScalar(wire.Challenge)
	if err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	pk, err := FromWireBundle(wire.Pk)
	if err != nil {
		return nil, fmt.Errorf("decode pk: %w", err)
	}
	pi, err := FromWireBundle(wire.Pi)
	if err != nil {
		return nil, fmt.Errorf("decode pi: %w", err)
	}
	vk, err := FromWireBundle(wire.Vk)
	if err != nil {
		return nil, fmt.Errorf("decode vk: %w", err)
	}
	return &tmps.ProofInput{
		Pk:        pk,
		Challenge: challenge,
		Pi:        pi,
		Vk:        vk,
	}, nil
}

func ToWireBundle(bundle *tmps.Bundle) (*Bundle, error) {
	if bundle == nil {
		return nil, nil
	}
	wire := &Bundle{
		G1:      make([]string, 0, len(bundle.G1)),
		G2:      make([]string, 0, len(bundle.G2)),
		GT:      make([]string, 0, len(bundle.GT)),
		Scalars: make([]string, 0, len(bundle.Scalars)),
	}
	for i, point := range bundle.G1 {
		if point == nil {
			return nil, fmt.Errorf("g1[%d] must not be nil", i)
		}
		wire.G1 = append(wire.G1, EncodeG1(point))
	}
	for i, point := range bundle.G2 {
		if point == nil {
			return nil, fmt.Errorf("g2[%d] must not be nil", i)
		}
		wire.G2 = append(wire.G2, EncodeG2(point))
	}
	for i, element := range bundle.GT {
		if element == nil {
			return nil, fmt.Errorf("gt[%d] must not be nil", i)
		}
		wire.GT = append(wire.GT, EncodeGT(element))
	}
	for i, scalar := range bundle.Scalars {
		if scalar == nil {
			return nil, fmt.Errorf("scalars[%d] must not be nil", i)
		}
		wire.Scalars = append(wire.Scalars, encodeScalar(scalar))
	}
	if len(wire.G1) == 0 {
		wire.G1 = nil
	}
	if len(wire.G2) == 0 {
		wire.G2 = nil
	}
	if len(wire.GT) == 0 {
		wire.GT = nil
	}
	if len(wire.Scalars) == 0 {
		wire.Scalars = nil
	}
	return wire, nil
}

func FromWireBundle(wire *Bundle) (*tmps.Bundle, error) {
	if wire == nil {
		return nil, nil
	}
	out := &tmps.Bundle{
		G1:      make([]*bn254.PointG1, 0, len(wire.G1)),
		G2:      make([]*bn254.PointG2, 0, len(wire.G2)),
		GT:      make([]*bn254.E, 0, len(wire.GT)),
		Scalars: make([]*big.Int, 0, len(wire.Scalars)),
	}
	for i, encoded := range wire.G1 {
		point, err := DecodeG1(encoded)
		if err != nil {
			return nil, fmt.Errorf("g1[%d]: %w", i, err)
		}
		out.G1 = append(out.G1, point)
	}
	for i, encoded := range wire.G2 {
		point, err := DecodeG2(encoded)
		if err != nil {
			return nil, fmt.Errorf("g2[%d]: %w", i, err)
		}
		out.G2 = append(out.G2, point)
	}
	for i, encoded := range wire.GT {
		element, err := DecodeGT(encoded)
		if err != nil {
			return nil, fmt.Errorf("gt[%d]: %w", i, err)
		}
		out.GT = append(out.GT, element)
	}
	for i, encoded := range wire.Scalars {
		scalar, err := decodeScalar(encoded)
		if err != nil {
			return nil, fmt.Errorf("scalars[%d]: %w", i, err)
		}
		out.Scalars = append(out.Scalars, scalar)
	}
	if len(out.G1) == 0 {
		out.G1 = nil
	}
	if len(out.G2) == 0 {
		out.G2 = nil
	}
	if len(out.GT) == 0 {
		out.GT = nil
	}
	if len(out.Scalars) == 0 {
		out.Scalars = nil
	}
	return out, nil
}

func EncodeG1(point *bn254.PointG1) string {
	return encodeHexBytes(bn254.NewG1().ToBytes(point))
}

func DecodeG1(encoded string) (*bn254.PointG1, error) {
	raw, err := decodeHexBytes(encoded, 64)
	if err != nil {
		return nil, err
	}
	group := bn254.NewG1()
	point, err := group.FromBytes(raw)
	if err != nil {
		return nil, err
	}
	if !group.InCorrectSubgroup(point) {
		return nil, fmt.Errorf("point is not in the correct G1 subgroup")
	}
	return point, nil
}

func EncodeG2(point *bn254.PointG2) string {
	return encodeHexBytes(bn254.NewG2().ToBytes(point))
}

func DecodeG2(encoded string) (*bn254.PointG2, error) {
	raw, err := decodeHexBytes(encoded, 128)
	if err != nil {
		return nil, err
	}
	group := bn254.NewG2()
	point, err := group.FromBytes(raw)
	if err != nil {
		return nil, err
	}
	if !group.InCorrectSubgroup(point) {
		return nil, fmt.Errorf("point is not in the correct G2 subgroup")
	}
	return point, nil
}

func EncodeGT(element *bn254.E) string {
	return encodeHexBytes(bn254.NewGT().ToBytes(element))
}

func DecodeGT(encoded string) (*bn254.E, error) {
	raw, err := decodeHexBytes(encoded, 384)
	if err != nil {
		return nil, err
	}
	return bn254.NewGT().FromBytes(raw)
}

func encodeScalar(value *big.Int) string {
	return new(big.Int).Set(value).String()
}

func decodeScalar(value string) (*big.Int, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("scalar must not be empty")
	}
	scalar, ok := new(big.Int).SetString(trimmed, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal scalar: %s", value)
	}
	if scalar.Sign() < 0 {
		return nil, fmt.Errorf("scalar must not be negative")
	}
	return scalar, nil
}

func encodeHexBytes(raw []byte) string {
	return "0x" + hex.EncodeToString(raw)
}

func decodeHexBytes(value string, expectedLen int) ([]byte, error) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(value, "0x"))
	if trimmed == "" {
		return nil, fmt.Errorf("hex value must not be empty")
	}
	raw, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, err
	}
	if expectedLen >= 0 && len(raw) != expectedLen {
		return nil, fmt.Errorf("invalid byte length: got %d want %d", len(raw), expectedLen)
	}
	return raw, nil
}
