package bls_threshold

import "blockchain-crypto/signature/bls/bn254/dependency/bls"

// SecKeyShareApi 私钥秘密分享
// 对私钥进行秘密分享
// 输入格式：私钥，门限值，总份额数
// 输出格式： ID 数组，私钥数组，公钥数组
func SecKeyShareApi(seck []byte, t int, n int) (ids [][]byte, secks [][]byte, pubks [][]byte) {
	bls.Init(bls.CurveFp254BNb)
	var sk bls.SecretKey
	sk.SetLittleEndian(seck)
	msk := sk.GetMasterSecretKey(t)
	mpk := bls.GetMasterPublicKey(msk)
	idVec := make([]bls.ID, n)
	secVec := make([]bls.SecretKey, n)
	pubVec := make([]bls.PublicKey, n)
	idVecStr := make([][]byte, n)
	secVecStr := make([][]byte, n)
	pubVecStr := make([][]byte, n)
	for i := 0; i < n; i++ {
		idVec[i].SetLittleEndian([]byte{byte(i & 255), byte(i >> 8), 2, 3, 4, 5})
		idVecStr[i] = idVec[i].GetLittleEndian()
		secVec[i].Set(msk, &idVec[i])
		secVecStr[i] = secVec[i].GetLittleEndian()
		pubVec[i].Set(mpk, &idVec[i])
		pubVecStr[i] = pubVec[i].Serialize()
	}
	return idVecStr, secVecStr, pubVecStr
}

// SecKeyRecoverApi 私钥恢复
// 从多个私钥份额中恢复出私钥
// 输入格式： ID 数组，私钥数组
// 输出格式：是否正确运行，恢复的私钥
func SecKeyRecoverApi(ids [][]byte, secks [][]byte) (isSuccess bool, seck []byte) {
	bls.Init(bls.CurveFp254BNb)
	if len(ids) != len(secks) {
		return false, []byte("incompatible length")
	}
	k := len(ids)
	idVec := make([]bls.ID, k)
	secVec := make([]bls.SecretKey, k)
	for i := 0; i != k; i++ {
		idVec[i].SetLittleEndian(ids[i])
		secVec[i].SetLittleEndian(secks[i])
	}
	var sec bls.SecretKey
	_ = sec.Recover(secVec, idVec)
	secKeyReBytes := sec.GetLittleEndian()
	return true, secKeyReBytes
}

// SigRecoverApi 签名恢复
// 从多个签名份额中恢复出签名
// 输入格式：ID数组，签名数组
// 输出格式：是否正确运行，恢复的签名
func SigRecoverApi(ids [][]byte, sigs [][]byte) (isSuccess bool, sig []byte) {
	bls.Init(bls.CurveFp254BNb)
	if len(ids) != len(sigs) {
		return false, []byte("incompatible length")
	}
	k := len(ids)
	idVec := make([]bls.ID, k)
	sigVec := make([]bls.Sign, k)
	for i := 0; i != k; i++ {
		idVec[i].SetLittleEndian(ids[i])
		sigVec[i].Deserialize(sigs[i])
	}
	var sign bls.Sign
	_ = sign.Recover(sigVec, idVec)
	sigReBytes := sign.Serialize()
	return true, sigReBytes
}

// PubKeyRecoverApi 公钥恢复
// 从多个公钥份额中恢复出公钥
// 输入格式： ID 数组，公钥数组
// 输出格式：是否正确运行，恢复的公钥
func PubKeyRecoverApi(ids [][]byte, pubks [][]byte) (isSuccess bool, pubk []byte) {
	bls.Init(bls.CurveFp254BNb)
	if len(ids) != len(pubks) {
		return false, []byte("incompatible length")
	}
	k := len(ids)
	idVec := make([]bls.ID, k)
	pubVec := make([]bls.PublicKey, k)
	for i := 0; i != k; i++ {
		idVec[i].SetLittleEndian(ids[i])
		pubVec[i].Deserialize(pubks[i])
	}
	var pub bls.PublicKey
	_ = pub.Recover(pubVec, idVec)
	pubKeyReBytes := pub.Serialize()
	return true, pubKeyReBytes
}
