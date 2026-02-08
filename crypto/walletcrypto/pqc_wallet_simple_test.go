//go:build cgo

package walletcrypto

import (
	"testing"
)

// TestPQCWalletSimple 最简化的后量子钱包测试
func TestPQCWalletSimple(t *testing.T) {
	t.Log("步骤 1: 生成 ML-DSA 密钥对...")
	keyPair, err := GenerateKeyPair(AlgPQMLDSA)
	if err != nil {
		t.Fatalf("密钥生成失败: %v", err)
	}
	t.Logf("✅ 公钥长度: %d, 私钥长度: %d", len(keyPair.PublicKey), len(keyPair.PrivateKey))

	t.Log("\n步骤 2: 签名...")
	message := []byte("test-transaction-data")
	sig, err := SignMessage(AlgPQMLDSA, keyPair.PrivateKey, message)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	t.Logf("✅ 签名长度: %d", len(sig))

	t.Log("\n步骤 3: 验签...")
	isValid, err := VerifyMessage(AlgPQMLDSA, keyPair.PublicKey, message, sig)
	if err != nil {
		t.Fatalf("验签失败: %v", err)
	}
	if !isValid {
		t.Fatal("验签返回false")
	}
	t.Log("✅ 验签成功！")
}
