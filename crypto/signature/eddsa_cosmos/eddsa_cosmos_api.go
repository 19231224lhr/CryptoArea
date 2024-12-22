package eddsa_cosmos

import "blockchain-crypto/signature/eddsa_cosmos/dependency"

// 所有 api 函数的输入输出均为由字节数组转化成的字符串（验证输出是bool）

// KeygenApi 密钥生成
// 随机生成公私钥对并输出
// 输出格式：私钥，公钥
func KeygenApi() ([]byte, []byte) {
	sk := ed25519.GenPrivKey()
	pk := sk.PubKey().(*ed25519.PubKey)
	sec := ed25519.PrivKey{Key: sk.Key}
	skbyte, _ := sec.Marshal()
	pub := ed25519.PubKey{Key: pk.Key}
	pkbyte, _ := pub.Marshal()
	return skbyte, pkbyte
}

func KeygenWithSeedAPI(seed []byte) ([]byte, []byte) {
	sk := ed25519.GenPrivKeyFromSecret(seed)
	pk := sk.PubKey().(*ed25519.PubKey)
	sec := ed25519.PrivKey{Key: sk.Key}
	skbyte, _ := sec.Marshal()
	pub := ed25519.PubKey{Key: pk.Key}
	pkbyte, _ := pub.Marshal()
	return skbyte, pkbyte
}

// SignApi 签名生成
// 对指定消息进行签名，输入消息将使用 sha512 进行 hash ，无需预先 hash
// 输入格式：私钥，消息
// 输出格式：签名
func SignApi(seck []byte, mes []byte) []byte {
	var sk ed25519.PrivKey
	sk.Unmarshal(seck)
	sign, _ := sk.Sign(mes)
	return sign
}

// VerifyApi 签名验证
// 对消息签名进行验证
// 输入格式：公钥，消息，签名
// 输出格式：是否正确（0表示否，1表示是）
func VerifyApi(pubk []byte, mes []byte, sig []byte) bool {
	var pk ed25519.PubKey
	pk.Unmarshal(pubk)
	return pk.VerifySignature(mes, sig)
}
