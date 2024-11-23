package signature

import "C"

import (
	bls "blockchain-crypto/signature/bls/bls12381"
	"blockchain-crypto/signature/ec_schnorr"
	"blockchain-crypto/signature/ecdsa"
	"blockchain-crypto/signature/eddsa"
	"blockchain-crypto/signature/eddsa_cosmos"
	"blockchain-crypto/signature/sm2"
	"bytes"
)

func KeygenAPI(scheme string) ([]byte, []byte) {
	switch scheme {
	case "bls":
		{
			return bls.KeygenAPI()
		}
	case "ecdsa":
		{
			return ecdsa.KeygenApi()
		}
	case "ec_schnorr":
		{
			return ec_schnorr.KeygenApi()
		}
	case "eddsa":
		{
			return ec_schnorr.KeygenApi()
		}
	case "eddsa_cosmos":
		{
			return eddsa_cosmos.KeygenApi()
		}
	case "sm2":
		{
			return sm2.KeygenApi()
		}
	default:
		{
			println("Wrong scheme name.")
			return nil, nil
		}
	}
}

func KeygenWithSeedAPI(scheme string, seed []byte) ([]byte, []byte) {
	switch scheme {
	case "bls":
		{
			return bls.KeygenWithSeedAPI(seed)
		}
	case "ecdsa":
		{
			return ecdsa.KeygenWithSeedAPI(seed)
		}
	case "ec_schnorr":
		{
			return ec_schnorr.KeygenWithSeedAPI(seed)
		}
	case "eddsa":
		{
			return eddsa.KeygenWithSeedAPI(seed)
		}
	case "eddsa_cosmos":
		{
			return eddsa_cosmos.KeygenWithSeedAPI(seed)
		}
	case "sm2":
		{
			return sm2.KeygenWithSeedAPI(seed)
		}
	default:
		{
			println("Wrong scheme name.")
			return nil, nil
		}
	}
}

func KeygenExtendAPI(scheme string, t uint8) ([][]byte, [][]byte) {
	sk := make([][]byte, t)
	pk := make([][]byte, t)
	switch scheme {
	case "bls":
		{
			for i := uint8(0); i < t; i++ {
				sk[i], pk[i] = bls.KeygenAPI()
			}
			return sk, pk
		}
	case "ecdsa":
		{
			for i := uint8(0); i < t; i++ {
				sk[i], pk[i] = ecdsa.KeygenApi()
			}
			return sk, pk
		}
	case "ec_schnorr":
		{
			for i := uint8(0); i < t; i++ {
				sk[i], pk[i] = ec_schnorr.KeygenApi()
			}
			return sk, pk
		}
	case "eddsa":
		{
			for i := uint8(0); i < t; i++ {
				sk[i], pk[i] = eddsa.KeygenApi()
			}
			return sk, pk
		}
	case "eddsa_cosmos":
		{

			for i := uint8(0); i < t; i++ {
				sk[i], pk[i] = eddsa_cosmos.KeygenApi()
			}
			return sk, pk
		}
	case "sm2":
		{
			for i := uint8(0); i < t; i++ {
				sk[i], pk[i] = sm2.KeygenApi()
			}
			return sk, pk
		}
	default:
		{
			println("Wrong scheme name.")
			return nil, nil
		}
	}
}

func SignAPI(scheme string, sk []byte, mes []byte) []byte {
	switch scheme {
	case "bls":
		{
			return bls.SignAPI(sk, mes)
		}
	case "ecdsa":
		{
			return ecdsa.SignApi(sk, mes)
		}
	case "ec_schnorr":
		{

			return ec_schnorr.SignApi(sk, mes)
		}
	case "eddsa":
		{
			return eddsa.SignApi(sk, mes)
		}
	case "eddsa_cosmos":
		{
			return eddsa_cosmos.SignApi(sk, mes)
		}
	case "sm2":
		{
			return sm2.SignApi(sk, mes)
		}
	default:
		{
			println("Wrong scheme name.")
			return nil
		}
	}
}

func VerifyApi(scheme string, pk []byte, mes []byte, sig []byte) bool {
	var result bool
	switch scheme {
	case "bls":
		{
			result = bls.VerifyAPI(pk, mes, sig)
		}
	case "ecdsa":
		{
			result = ecdsa.VerifyApi(pk, mes, sig)
		}
	case "ec_schnorr":
		{
			result = ec_schnorr.VerifyApi(pk, mes, sig)
		}
	case "eddsa":
		{
			result = eddsa.VerifyApi(pk, mes, sig)
		}
	case "eddsa_cosmos":
		{
			result = eddsa_cosmos.VerifyApi(pk, mes, sig)
		}
	case "sm2":
		{
			result = sm2.VerifyApi(pk, mes, sig)
		}
	default:
		{
			println("Wrong scheme name.")
		}
	}
	return result
}

func VerifyKeyGen(scheme string, forwardPK, backwardSK, backwardPK []byte) bool {
	switch scheme {
	case "bls":
		{
			expectedSK, expectedPK := bls.KeygenWithSeedAPI(forwardPK)
			return bytes.Equal(expectedSK, backwardSK) && bytes.Equal(expectedPK, backwardPK)
		}
	case "ecdsa":
		{
			expectedSK, expectedPK := ecdsa.KeygenWithSeedAPI(forwardPK)
			return bytes.Equal(expectedSK, backwardSK) && bytes.Equal(expectedPK, backwardPK)
		}
	case "ec_schnorr":
		{
			expectedSK, expectedPK := ec_schnorr.KeygenWithSeedAPI(forwardPK)
			return bytes.Equal(expectedSK, backwardSK) && bytes.Equal(expectedPK, backwardPK)
		}
	case "eddsa":
		{
			expectedSK, expectedPK := eddsa.KeygenWithSeedAPI(forwardPK)
			return bytes.Equal(expectedSK, backwardSK) && bytes.Equal(expectedPK, backwardPK)
		}
	case "eddsa_cosmos":
		{
			expectedSK, expectedPK := eddsa_cosmos.KeygenWithSeedAPI(forwardPK)
			return bytes.Equal(expectedSK, backwardSK) && bytes.Equal(expectedPK, backwardPK)
		}
	case "sm2":
		{
			expectedSK, expectedPK := sm2.KeygenWithSeedAPI(forwardPK)
			return bytes.Equal(expectedSK, backwardSK) && bytes.Equal(expectedPK, backwardPK)
		}
	default:
		{
			println("Wrong scheme name.")
			return false
		}
	}
}
