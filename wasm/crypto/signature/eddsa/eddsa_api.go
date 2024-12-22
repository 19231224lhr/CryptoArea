package eddsa

import (
	"blockchain-crypto/signature/eddsa/dependency"
	"crypto/rand"
)

// 所有 api 函数的输入输出均为由字节数组转化成的字符串（验证输出是 bool ）

// KeygenApi 密钥生成
// 随机生成公私钥对并输出
// 输出格式：私钥，公钥
func KeygenApi() ([]byte, []byte) {
	pk, sk, _ := dependency.GenerateKey(rand.Reader)
	return sk, pk
}

func KeygenWithSeedAPI(seed []byte) (seck []byte, pubk []byte) {
	pk, sk, _ := dependency.GenerateKeyFromSeed(seed)
	return sk, pk
}

// SignApi 签名生成
// 对指定消息进行签名，输入消息将使用 sha512 进行 hash ，无需预先 hash
// 输入格式：私钥，消息
// 输出格式：签名
func SignApi(sk []byte, msg []byte) (sig []byte) {
	return dependency.Sign(sk, msg)
}

// VerifyApi 签名验证
// 对消息签名进行验证
// 输入格式：公钥，消息，签名
// 输出格式：是否正确（0表示否，1表示是）
func VerifyApi(pk []byte, mes []byte, sig []byte) bool {
	return dependency.Verify(pk, mes, sig)
}
