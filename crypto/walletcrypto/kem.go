package walletcrypto

import (
	"fmt"
	"strings"
	"teddycode/pqcgo"
)

var kemAliases = map[string]string{
	AlgPQMLKEM512:  "ml_kem_512",
	AlgPQMLKEM768:  "ml_kem_768",
	AlgPQMLKEM1024: "ml_kem_1024",
	AlgPQAigisEnc1: "aigis_enc_1",
	AlgPQAigisEnc2: "aigis_enc_2",
	AlgPQAigisEnc3: "aigis_enc_3",
	AlgPQAigisEnc4: "aigis_enc_4",
}

func GenerateKEMKeyPair(algorithm string) (*KeyPair, error) {
	scheme, canonical, err := resolveKEMAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	pk, sk, err := pqcgo.KEMKeyGen(scheme)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		Algorithm:  canonical,
		PrivateKey: sk,
		PublicKey:  pk,
	}, nil
}

func EncapsulateSharedSecret(algorithm string, publicKey []byte) ([]byte, []byte, error) {
	scheme, _, err := resolveKEMAlgorithm(algorithm)
	if err != nil {
		return nil, nil, err
	}
	if len(publicKey) == 0 {
		return nil, nil, fmt.Errorf("public key must not be empty")
	}

	return pqcgo.KEMEncapsulate(scheme, publicKey)
}

func DecapsulateSharedSecret(algorithm string, privateKey []byte, ciphertext []byte) ([]byte, error) {
	scheme, _, err := resolveKEMAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	if len(privateKey) == 0 {
		return nil, fmt.Errorf("private key must not be empty")
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext must not be empty")
	}

	return pqcgo.KEMDecapsulate(scheme, ciphertext, privateKey)
}

func resolveKEMAlgorithm(algorithm string) (int, string, error) {
	normalized := strings.ToLower(strings.TrimSpace(algorithm))
	if normalized == "" {
		return -1, "", fmt.Errorf("algorithm must not be empty")
	}

	if kemName, ok := kemAliases[normalized]; ok {
		scheme, err := pqcgo.ParseKEMSchemeName(kemName)
		if err != nil {
			return -1, "", err
		}
		return scheme, normalized, nil
	}

	if strings.HasPrefix(normalized, "pq_") {
		normalized = strings.TrimPrefix(normalized, "pq_")
	}

	scheme, err := pqcgo.ParseKEMSchemeName(normalized)
	if err != nil {
		return -1, "", fmt.Errorf("unsupported kem algorithm: %s", algorithm)
	}

	return scheme, "pq_" + normalized, nil
}
