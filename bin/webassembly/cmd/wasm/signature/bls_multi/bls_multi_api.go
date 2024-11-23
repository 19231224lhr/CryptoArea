package bls_multi

import (
	"blockchain-crypto/signature/bls/bn254/dependency/bls"
	"blockchain-crypto/signature/bls_multi/dependency/groupsig"
)

// Chinese notes encode by UTF-8

// 所有 api 函数的输入输出均为 16 进制（验证输出是 bool ）
// 需要输入输出多个时使用数组

// KeygenApi 密钥生成
// 随机生成公私钥对并输出
// 输出格式：私钥，公钥
func KeygenApi() (seck []byte, pubk []byte) {
	bls.Init(bls.CurveFp254BNb)
	var sk bls.SecretKey
	sk.SetByCSPRNG()
	pk := sk.GetPublicKey()
	return sk.GetLittleEndian(), pk.Serialize()
}

// SignApi 签名生成
// 对指定消息进行签名，与 bls 一致
// 输入格式：私钥，消息
// 输出格式：签名
func SignApi(seck []byte, mes []byte) (sig []byte) {
	bls.Init(bls.CurveFp254BNb)
	var sk bls.SecretKey
	sk.SetLittleEndian(seck)
	sign := sk.Sign(string(mes))
	return sign.Serialize()
}

// MultiSignApi 签名整合
// 将多个签名整合为一个多重签名
// 输入格式：签名数组
// 输出格式：签名
func MultiSignApi(sigs [][]byte) (multiSig []byte) {
	bls.Init(bls.CurveFp254BNb)
	var signs []groupsig.Signature
	signs = make([]groupsig.Signature, len(sigs))
	for i := 0; i < len(sigs); i++ {
		signs[i].Deserialize(sigs[i])
	}
	mulsig := groupsig.AggregateSigs(signs)
	return mulsig.Serialize()
}

// MultiVerifyApi 多重签名验证
// 将多个公钥整合为一个公钥，再验证多重签名
// 输入格式：公钥数组，消息，多重签名
// 输出格式：签名是否有效
func MultiVerifyApi(pubks [][]byte, mes []byte, mulsig []byte) bool {
	bls.Init(bls.CurveFp254BNb)
	var pks []groupsig.Pubkey
	pks = make([]groupsig.Pubkey, len(pubks))
	for i := 0; i < len(pubks); i++ {
		pks[i].Deserialize(pubks[i])
	}
	m := []byte(string(mes))
	var msig groupsig.Signature
	msig.Deserialize(mulsig)
	return groupsig.VerifyAggregateSig(pks, m, msig)
}
