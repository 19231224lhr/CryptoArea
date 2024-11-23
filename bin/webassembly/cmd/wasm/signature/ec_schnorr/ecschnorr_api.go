package ec_schnorr

import (
	"blockchain-crypto/signature/ec_schnorr/dependency"
	"crypto/elliptic"
)

// KeygenApi 密钥生成
// 随机生成公私钥对并输出
// 输出格式：私钥，公钥
// 均为字符串
func KeygenApi() (skBytes []byte, pkBytes []byte) {
	sk, _ := dependency.GenerateKey(elliptic.P256())
	secStr, _ := dependency.GetEcdsaPrivateKeyJsonFormat(sk)
	pubStr, _ := dependency.GetEcdsaPublicKeyJsonFormat(sk)
	return []byte(secStr), []byte(pubStr)
}

func KeygenWithSeedAPI(seed []byte) (skBytes []byte, pkBytes []byte) {
	sk, _ := dependency.GenerateKeyBySeed(elliptic.P256(), seed)
	secStr, _ := dependency.GetEcdsaPrivateKeyJsonFormat(sk)
	pubStr, _ := dependency.GetEcdsaPublicKeyJsonFormat(sk)
	return []byte(secStr), []byte(pubStr)
}

// SignApi 签名生成
// 对指定消息进行签名，输入消息无需预先 hash
// 输入格式：私钥，消息
// 输出格式：签名 r ，签名 s
// 输入输出均为字符串
func SignApi(seck []byte, mes []byte) (sig []byte) {
	sk, _ := dependency.GetEcdsaPrivateKeyFromJsonStr(string(seck))
	sign, _ := dependency.Sign(sk, mes)
	return sign
}

// VerifyApi 签名验证
// 对消息签名进行验证
// 输入格式：公钥，消息，签名 r ，签名 s
// 输出格式：是否正确（0表示否，1表示是）
// 输入为字符串，输出为 bool 变量
func VerifyApi(pubk []byte, mes []byte, sig []byte) bool {
	pk, _ := dependency.GetEcdsaPublicKeyFromJsonStr(string(pubk))
	result, _ := dependency.Verify(pk, sig, mes)
	return result
}
