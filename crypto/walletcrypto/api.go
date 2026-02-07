package walletcrypto

import (
	"blockchain-crypto/signature"
	"fmt"
	"strings"
	"teddycode/pqcgo"
)

type algorithmKind int

const (
	algorithmKindClassical algorithmKind = iota
	algorithmKindPQC
)

type resolvedAlgorithm struct {
	Kind      algorithmKind
	Classical string
	PQCScheme int
	Canonical string
}

var classicalAlgorithms = map[string]struct{}{
	AlgBLS:         {},
	AlgECDSA:       {},
	AlgECSchnorr:   {},
	AlgEdDSA:       {},
	AlgEdDSACosmos: {},
	AlgSM2:         {},
}

var pqcAliases = map[string]string{
	AlgPQAigisSig:  "aigis_sig",
	AlgPQDilithium: "dilithium",
	AlgPQMLDSA:     "ml_dsa",
	AlgPQSLHDSA:    "slh_dsa",
}

func GenerateKeyPair(algorithm string) (*KeyPair, error) {
	resolved, err := resolveAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	switch resolved.Kind {
	case algorithmKindClassical:
		sk, pk := signature.KeygenAPI(resolved.Classical)
		if len(sk) == 0 || len(pk) == 0 {
			return nil, fmt.Errorf("key generation failed for algorithm: %s", resolved.Classical)
		}
		return &KeyPair{
			Algorithm:  resolved.Canonical,
			PrivateKey: sk,
			PublicKey:  pk,
		}, nil
	case algorithmKindPQC:
		pk, sk, err := pqcgo.KeyGen(resolved.PQCScheme)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			Algorithm:  resolved.Canonical,
			PrivateKey: sk,
			PublicKey:  pk,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm kind")
	}
}

func GenerateKeyPairWithSeed(algorithm string, seed []byte) (*KeyPair, error) {
	if len(seed) == 0 {
		return nil, fmt.Errorf("seed must not be empty")
	}

	resolved, err := resolveAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	switch resolved.Kind {
	case algorithmKindClassical:
		sk, pk := signature.KeygenWithSeedAPI(resolved.Classical, seed)
		if len(sk) == 0 || len(pk) == 0 {
			return nil, fmt.Errorf("key generation with seed failed for algorithm: %s", resolved.Classical)
		}
		return &KeyPair{
			Algorithm:  resolved.Canonical,
			PrivateKey: sk,
			PublicKey:  pk,
		}, nil
	case algorithmKindPQC:
		pk, sk, err := pqcgo.KeyGenWithSeed(resolved.PQCScheme, seed)
		if err != nil {
			return nil, err
		}
		return &KeyPair{
			Algorithm:  resolved.Canonical,
			PrivateKey: sk,
			PublicKey:  pk,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm kind")
	}
}

func SignMessage(algorithm string, privateKey []byte, message []byte) ([]byte, error) {
	resolved, err := resolveAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("private key must not be empty")
	}

	switch resolved.Kind {
	case algorithmKindClassical:
		sig := signature.SignAPI(resolved.Classical, privateKey, message)
		if len(sig) == 0 {
			return nil, fmt.Errorf("signing failed for algorithm: %s", resolved.Classical)
		}
		return sig, nil
	case algorithmKindPQC:
		return pqcgo.Sign(resolved.PQCScheme, message, privateKey)
	default:
		return nil, fmt.Errorf("unsupported algorithm kind")
	}
}

func VerifyMessage(algorithm string, publicKey []byte, message []byte, signatureBytes []byte) (bool, error) {
	resolved, err := resolveAlgorithm(algorithm)
	if err != nil {
		return false, err
	}
	if len(publicKey) == 0 {
		return false, fmt.Errorf("public key must not be empty")
	}
	if len(signatureBytes) == 0 {
		return false, fmt.Errorf("signature must not be empty")
	}

	switch resolved.Kind {
	case algorithmKindClassical:
		ok := signature.VerifyAPI(resolved.Classical, publicKey, message, signatureBytes)
		return ok, nil
	case algorithmKindPQC:
		return pqcgo.Verify(resolved.PQCScheme, signatureBytes, message, publicKey)
	default:
		return false, fmt.Errorf("unsupported algorithm kind")
	}
}

func resolveAlgorithm(algorithm string) (resolvedAlgorithm, error) {
	normalized := strings.ToLower(strings.TrimSpace(algorithm))
	if normalized == "" {
		return resolvedAlgorithm{}, fmt.Errorf("algorithm must not be empty")
	}

	if _, ok := classicalAlgorithms[normalized]; ok {
		return resolvedAlgorithm{
			Kind:      algorithmKindClassical,
			Classical: normalized,
			Canonical: normalized,
		}, nil
	}

	if pqName, ok := pqcAliases[normalized]; ok {
		scheme, err := pqcgo.ParseSchemeName(pqName)
		if err != nil {
			return resolvedAlgorithm{}, err
		}
		return resolvedAlgorithm{
			Kind:      algorithmKindPQC,
			PQCScheme: scheme,
			Canonical: normalized,
		}, nil
	}

	scheme, err := pqcgo.ParseSchemeName(normalized)
	if err == nil {
		return resolvedAlgorithm{
			Kind:      algorithmKindPQC,
			PQCScheme: scheme,
			Canonical: "pq_" + normalized,
		}, nil
	}

	return resolvedAlgorithm{}, fmt.Errorf("unsupported algorithm: %s", algorithm)
}
