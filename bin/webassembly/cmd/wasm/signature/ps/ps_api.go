package ps

import "C"
import (
	"blockchain-crypto/signature/ps/dependency"
)

// 存在问题：参数不知道该怎么导入

// 所有api函数的输入输出均为10进制字符串（验证输出是bool）

// 密钥生成
// 随机生成公私钥对并输出
// 输出格式：私钥，公钥
func KeygenApi() ([]string, []string) {
	var sk dependency.SecretKey
	sk.SetByRand()
	pk := sk.GetPublicKey()
	return sk.Serialize(), pk.Serialize()
}

// 签名生成
// 对指定消息进行签名，输入消息使用内置的hash函数进行hash运算
// 输入格式：私钥，消息
// 输出格式：签名
func SignApi(seck []string, mes string) []string {
	var sign dependency.Sign
	var sk dependency.SecretKey
	sk.Deserialize(seck)
	sign = *sk.Sign(mes)
	return sign.Serialize()
}

// 签名验证
// 对消息签名进行验证
// 输入格式：公钥，消息，签名
// 输出格式：是否正确（0表示否，1表示是）
func VerifyApi(pubk []string, mes string, sig []string) bool {
	var sign dependency.Sign
	var pk dependency.PublicKey
	pk.Deserialize(pubk)
	sign.Deserialize(sig)
	return sign.Verify(&pk, mes)
}
