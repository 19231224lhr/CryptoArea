package bn254

import "C"
import (
	"blockchain-crypto/signature/bls/bn254/dependency/bls"
)

// 所有 api 函数的输入输出均为 byte 数组（验证输出是 bool ）

// 密钥生成
// 随机生成公私钥对并输出
// 输出格式：私钥，公钥
func KeygenApi() (seck []byte, pubk []byte) {
	bls.Init(bls.CurveFp254BNb)
	var sk bls.SecretKey
	sk.SetByCSPRNG()
	pk := sk.GetPublicKey()
	return sk.GetLittleEndian(), pk.Serialize()
}

// 签名生成
// 对指定消息进行签名，输入消息使用内置的 hash 函数进行 hash 运算
// 输入格式：私钥，消息
// 输出格式：签名
func SignApi(seck []byte, mes []byte) (sig []byte) {
	bls.Init(bls.CurveFp254BNb)
	var sk bls.SecretKey
	sk.SetLittleEndian(seck)
	sign := sk.Sign(string(mes))
	return sign.Serialize()
}

// 签名验证
// 对消息签名进行验证
// 输入格式：公钥，消息，签名
// 输出格式：是否正确（0表示否，1表示是）
func VerifyApi(pubk []byte, mes []byte, sig []byte) bool {
	bls.Init(bls.CurveFp254BNb)
	var pk bls.PublicKey
	pk.Deserialize(pubk)
	var sign bls.Sign
	sign.Deserialize(sig)
	return sign.Verify(&pk, string(mes))
}
