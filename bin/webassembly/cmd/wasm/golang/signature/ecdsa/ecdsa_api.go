package ecdsa

import (
	"blockchain-crypto/signature/ecdsa/dependency"
)

// 所有api函数的输入输出均为由字节数组转化成的字符串（验证输出是bool）
// 使用序列化（Serialize）函数将结构体转化为字节数组，使用解析（Parse）函数将字节数组转化为结构体

// 密钥生成
// 随机生成公私钥对并输出
// 输出格式：私钥，公钥
func KeygenApi() (seck []byte, pubk []byte) {
	sk, _ := dependency.NewPrivateKey(dependency.S256())
	pk := sk.PubKey()
	return sk.Serialize(), pk.SerializeCompressed()
}

func KeygenWithSeedAPI(seed []byte) (seck []byte, pubk []byte) {
	sk, pk := dependency.PrivKeyFromBytes(dependency.S256(), seed)
	return sk.Serialize(), pk.SerializeCompressed()
}

// 签名生成
// 对指定消息进行签名，输入消息应先进行hash运算再输入
// 输入格式：私钥，消息
// 输出格式：签名
func SignApi(seck []byte, meshashed []byte) (sig []byte) {
	sk, _ := dependency.PrivKeyFromBytes(dependency.S256(), seck)
	sign, _ := sk.Sign(meshashed)
	return sign.Serialize()
}

// 签名验证
// 对消息签名进行验证
// 输入格式：公钥，消息，签名
// 输出格式：是否正确（0表示否，1表示是）
func VerifyApi(pubk []byte, meshashed []byte, sig []byte) bool {
	pk, _ := dependency.ParsePubKey(pubk, dependency.S256())
	sign, _ := dependency.ParseSignature(sig, dependency.S256())
	return sign.Verify(meshashed, pk)
}
