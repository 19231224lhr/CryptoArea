//go:build cgo

package walletcrypto

import (
	"testing"
)

// TestPQCWalletCompleteFlow 测试使用后量子密码的完整钱包流程
func TestPQCWalletCompleteFlow(t *testing.T) {
	// ========== 步骤 1: 生成后量子密钥对 ==========
	t.Log("步骤 1: 生成 ML-DSA 密钥对...")
	keyPair, err := GenerateKeyPair(AlgPQMLDSA)
	if err != nil {
		t.Fatalf("密钥生成失败: %v", err)
	}
	t.Logf("✅ 密钥对生成成功 - 公钥: %d bytes, 私钥: %d bytes",
		len(keyPair.PublicKey), len(keyPair.PrivateKey))

	// ========== 步骤 2: 生成钱包地址 ==========
	t.Log("\n步骤 2: 生成钱包地址...")

	addressBTC, err := GenerateAddress(keyPair.PublicKey, &AddressOptions{
		Format:  AddressFormatBase58Check,
		Version: 0x00,
	})
	if err != nil {
		t.Fatalf("地址生成失败: %v", err)
	}
	t.Logf("✅ 钱包地址: %s", addressBTC)

	// ========== 步骤 3: 签名交易 ==========
	t.Log("\n步骤 3: 签名交易...")

	txBytes := []byte("transaction-data-from-alice-to-bob-amount-100")

	signature, err := SignMessage(AlgPQMLDSA, keyPair.PrivateKey, txBytes)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	t.Logf("✅ 签名成功 - 签名长度: %d bytes", len(signature))

	// ========== 步骤 4: 验证签名 ==========
	t.Log("\n步骤 4: 验证签名...")

	isValid, err := VerifyMessage(AlgPQMLDSA, keyPair.PublicKey, txBytes, signature)
	if err != nil {
		t.Fatalf("验签失败: %v", err)
	}
	if !isValid {
		t.Fatal("签名验证失败")
	}
	t.Log("✅ 签名验证成功！交易合法")

	// 测试防篡改
	t.Log("\n步骤 4.1: 测试防篡改...")
	tamperedTx := []byte("transaction-data-from-alice-to-eve-amount-999")

	isValidTampered, _ := VerifyMessage(AlgPQMLDSA, keyPair.PublicKey, tamperedTx, signature)
	if isValidTampered {
		t.Fatal("⚠️ 安全漏洞：篡改的交易验签通过了！")
	}
	t.Log("✅ 防篡改测试通过")

	// ========== 步骤 5: 私钥加密存储 ==========
	t.Log("\n步骤 5: 加密存储私钥...")

	password := []byte("SecurePassword123!")

	keystoreData, err := EncryptPrivateKey(keyPair.PrivateKey, password)
	if err != nil {
		t.Fatalf("私钥加密失败: %v", err)
	}
	t.Logf("✅ 私钥加密成功 - Keystore: %d bytes", len(keystoreData))

	// 解密恢复
	decryptedPrivKey, err := DecryptPrivateKey(keystoreData, password)
	if err != nil {
		t.Fatalf("私钥解密失败: %v", err)
	}

	// 验证一致性
	match := len(decryptedPrivKey) == len(keyPair.PrivateKey)
	if match {
		for i := range keyPair.PrivateKey {
			if decryptedPrivKey[i] != keyPair.PrivateKey[i] {
				match = false
				break
			}
		}
	}
	if !match {
		t.Fatal("解密后私钥不匹配")
	}
	t.Log("✅ 私钥解密成功，内容一致")

	// 测试错误密码
	t.Log("\n步骤 5.1: 测试密码保护...")
	wrongPassword := []byte("WrongPassword")
	_, err = DecryptPrivateKey(keystoreData, wrongPassword)
	if err == nil {
		t.Fatal("⚠️ 安全漏洞：错误密码解密成功")
	}
	t.Log("✅ 密码保护测试通过")

	// ========== 步骤 6: 使用解密私钥签名 ==========
	t.Log("\n步骤 6: 使用解密私钥签名...")

	newTx := []byte("second-transaction-data")

	newSig, err := SignMessage(AlgPQMLDSA, decryptedPrivKey, newTx)
	if err != nil {
		t.Fatalf("使用解密私钥签名失败: %v", err)
	}

	isValidNew, err := VerifyMessage(AlgPQMLDSA, keyPair.PublicKey, newTx, newSig)
	if err != nil || !isValidNew {
		t.Fatal("解密私钥签名验签失败")
	}
	t.Log("✅ 解密私钥功能正常")

	// ========== 测试总结 ==========
	t.Log("\n============================================================")
	t.Log("🎉 后量子密码钱包完整流程测试通过！")
	t.Log("============================================================")
	t.Log("测试覆盖:")
	t.Log("  ✅ ML-DSA 密钥生成")
	t.Log("  ✅ Base58Check 地址生成")
	t.Log("  ✅ 后量子签名")
	t.Log("  ✅ 后量子验签")
	t.Log("  ✅ 防篡改测试")
	t.Log("  ✅ 私钥加密存储 (AES-256-GCM + PBKDF2)")
	t.Log("  ✅ 私钥解密恢复")
	t.Log("  ✅ 密码保护测试")
	t.Log("  ✅ 完整流程闭环验证")
}
