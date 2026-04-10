package post

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/19231224lhr/CryptoArea/crypto/compat/legacy"
)

func challengeDigest(profile ProfileName, payload []byte) ([]byte, error) {
	switch profile {
	case ProfileStrictV1:
		sum := sha256.Sum256(payload)
		out := make([]byte, len(sum))
		copy(out, sum[:])
		return out, nil
	case ProfileLegacyCompatV1:
		return legacy.SHA224(payload), nil
	default:
		return nil, fmt.Errorf("unsupported post profile: %s", profile)
	}
}

func witnessDigest(profile ProfileName, payload []byte) ([]byte, error) {
	return challengeDigest(profile, payload)
}

func responseDigest(profile ProfileName, key []byte, payload []byte) ([]byte, error) {
	switch profile {
	case ProfileStrictV1:
		mac := hmac.New(sha256.New, key)
		mac.Write(payload)
		return mac.Sum(nil), nil
	case ProfileLegacyCompatV1:
		return legacy.SHA256Concat(key, payload), nil
	default:
		return nil, fmt.Errorf("unsupported post profile: %s", profile)
	}
}
