package dependency

import (
	"crypto/elliptic"
	"testing"
)

func TestNewSchnorr(t *testing.T) {
	sk, _ := GenerateKey(elliptic.P256())
	strJsonPrivateKey, _ := GetEcdsaPrivateKeyJsonFormat(sk)
	privateKey, _ := GetEcdsaPrivateKeyFromJsonStr(strJsonPrivateKey)
	msg := []byte("Hello ecies!")
	println("Keygen finished.")

	// --- 验证new Schnorr签名算法 start ---

	sigma, _ := Sign(privateKey, msg)
	println("Sign finished.")
	//
	isSignatureMatch, _ := Verify(&privateKey.PublicKey, sigma, msg)
	println("Verify finished.")
	println("Verify result =", isSignatureMatch)
	// --- 验证new Schnorr签名算法 end ---
}
